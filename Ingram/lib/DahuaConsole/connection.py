from utils import *
from pwdmanager import PwdManager
from dahua import DahuaFunctions


class DahuaConnect(object):
    def __init__(self):
        super(DahuaConnect, self).__init__()

        self.dh = None
        self.dhConsole = {}
        self.dhConsoleNo = 0

        self.udp_server = None
        self.tcp_server = None
        self.dargs = None

    def restart_connection(self, host):
        """ Handle restart of connections, trying every 30sec for 10 times, if no success, stop trying """
        log.info('Scheduling reconnect to {}'.format(host))

        dh_data = PwdManager().find_host(host)
        times = 0

        while True:
            time.sleep(30)
            try:
                if not self.connect_rhost(
                        rhost=dh_data.get('host'),
                        rport=dh_data.get('port'),
                        proto=dh_data.get('proto'),
                        username=dh_data.get('username'),
                        password=None,
                        events=dh_data.get('events'),
                        ssl=self.dargs.ssl,
                        relay_host=dh_data.get('relay'),
                        logon=dh_data.get('logon'),
                        timeout=5):
                    print('[restart_connection] ({})'.format(times))
                    times += 1
                else:
                    return True
            # except Exception:
            except AttributeError:
                log.failure('[restart_connection] ({})'.format(host))
                pass

            if times == 10:
                log.failure('See you in valhalla {}'.format(host))
                return False

    def connect_rhost(
            self, rhost=None, rport=0, proto=None, username=None, password=None, events=None,
            ssl=None, relay_host=None, logon=None, timeout=0):
        """ Handling connection(s) to remote device """

        """ Check if RPORT is valid """
        if not check_port(rport):
            log.failure("Invalid RPORT - Choose between 1 and 65535")
            return False

        """ Check if RHOST is valid IP or FQDN, get IP back """
        if not check_host(rhost):
            return False

        for session in self.dhConsole:
            if self.dhConsole.get(session).get('host') == rhost:
                log.warning('Already connected to {}'.format(rhost))
                return False

        """ Needed for get 'self.udp_server' set """
        time.sleep(1)

        dh = DahuaFunctions(
            rhost=rhost,
            rport=rport,
            proto=proto,
            events=events,
            ssl=ssl,
            relay_host=relay_host,
            timeout=timeout,
            udp_server=self.udp_server,
            dargs=self.dargs
        )

        try:
            if not dh.dh_connect(username=username, password=password, logon=logon, force=self.dargs.force):
                return False
        except PwnlibException as e:
            print('[connect_rhost.dh_connect()]', repr(e))
            return False

        self.dh = dh
        if not self.dargs.test:
            self.dhConsole.update({
                'dh' + str(self.dhConsoleNo): {
                    'instance': self.dh,
                    'host': rhost,
                    'proto': proto,
                    'port': rport,
                    'device': self.dh.DeviceType,
                    'logon': logon,
                    'relay': relay_host,
                }
            })
            self.dhConsoleNo += 1

        return True
