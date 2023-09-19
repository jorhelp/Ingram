import select
import queue
import _thread
from utils import *
from events import DahuaEvents


class Servers(DahuaEvents):
    def __init__(self):
        super(Servers, self).__init__()

    #
    # Will terminate and restart instances in case of some failure
    #
    def terminate_daemons(self):

        time.sleep(1)
        if not self.udp_server:
            return False

        status = log.progress(color('Terminate Daemons thread', YELLOW))
        status.success(color('Started', GREEN))

        daemon = False

        while True:
            session = None
            instance = None
            host = None
            time.sleep(10)
            for session in self.dhConsole:
                instance = self.dhConsole.get(session).get('instance')
                if instance.terminate:  # and not instance.remote.connected():
                    host = self.dhConsole.get(session).get('host')
                    daemon = True
                    break

            try:
                if daemon:
                    self.dhConsole.pop(session)
                    if self.dh == instance:
                        for session in self.dhConsole:
                            self.dh = self.dhConsole.get(session).get('instance')
                            break
                    del instance
                    daemon = False
                    _thread.start_new_thread(self.restart_connection, (host,))
                    if not len(self.dhConsole):
                        log.failure('Terminate Daemons: No other active sessions')
                        return False

            except (Exception, PwnlibException) as e:
                status.failure('{}'.format(repr(e)))
                return False

    #
    # Will handle all incoming event traffic on UDP, accepting connections from TCP to relay event traffic
    # - The receiving UDP socket is literally connected to sending TCP socket
    # - Will also send to internal event handler, to catch some events
    # - Since it's unsorted JSON from multiple instances, the JSON needs to be fixed with 'fix_json()'
    #
    # Good info
    # https://steelkiwi.com/blog/working-tcp-sockets/
    def event_in_out_server(self):

        status = log.progress(color('UDP/TCP events server listener thread', YELLOW))

        try:
            self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_server.setblocking(False)
            self.tcp_server.bind(('127.0.0.1', EventOutServerPort))
            self.tcp_server.listen(10)

            self.udp_server = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            self.udp_server.bind(('127.0.0.1', EventInServerPort))

        except OSError as e:
            self.udp_server = False
            self.tcp_server = False
            status.failure(color("{}".format(e), RED))
            return False

        inputs = [self.tcp_server, self.udp_server]
        outputs = []
        message_queues = {}

        try:
            status.success(color("Started", GREEN))

            while True:

                readable, writable, exceptional = select.select(
                    inputs, outputs, inputs)

                for s in readable:
                    if s is self.tcp_server:
                        connection, client_address = s.accept()
                        # log.info('Connection: {}'.format(client_address))
                        connection.setblocking(0)
                        inputs.append(connection)
                        message_queues[connection] = queue.Queue()
                    else:
                        if s is not self.udp_server:
                            dh_data = s.recv(1024)
                            if s not in outputs:
                                outputs.append(s)
                            if not dh_data:
                                if s in outputs:
                                    outputs.remove(s)
                                inputs.remove(s)
                                s.close()
                                del message_queues[s]

                        else:
                            dh_data, address = self.udp_server.recvfrom(8192)
                            # log.info('Incoming data from: {}'.format(address))
                            if len(dh_data) == 8192:
                                log.warning('EventInOutServer: LEN == 8192')
                                print(dh_data)
                            if dh_data:
                                self.internal_event_manager(dh_data.decode('latin-1'))
                                for tmp in message_queues:
                                    message_queues[tmp].put(dh_data)
                                    if tmp not in outputs:
                                        outputs.append(tmp)

                for s in writable:
                    try:
                        next_msg = message_queues[s].get_nowait()
                    except queue.Empty:
                        outputs.remove(s)
                    else:
                        s.send(next_msg)

                for s in exceptional:
                    if s in inputs:
                        inputs.remove(s)
                    if s in outputs:
                        outputs.remove(s)
                    s.close()
                    del message_queues[s]

        except Exception as e:
            status.failure('{}'.format(repr(e)))
            return False
