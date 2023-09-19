import ast
import ndjson
import copy
import inspect
import _thread

from utils import *
from pwdmanager import PwdManager
from relay import init_relay, DahuaHttp


def dahua_proto(proto):
    """ DVRIP have different codes in their protocols """

    headers = [
        b'\xa0\x00',  # 3DES Login
        b'\xa0\x01',  # DVRIP Send Request Realm
        b'\xa0\x05',  # DVRIP login Send Login Details
        b'\xb0\x00',  # DVRIP Receive
        b'\xb0\x01',  # DVRIP Receive
        b'\xa3\x01',  # DVRIP Discover Request
        b'\xb3\x00',  # DVRIP Discover Response
        b'\xf6\x00',  # DVRIP JSON
    ]
    if proto[:2] in headers:
        return True
    return False


class Network(object):
    def __init__(self):
        super(Network, self).__init__()

        self.args = None

        """ If we don't have own udp server running in main app, will be False and we do not send anything """
        self.tcp_server = None

        self.console_attach = None
        self.DeviceClass = None
        self.DeviceType = None
        self.AuthCode = None
        self.ErrorCode = None

        # Internal sharing
        self.ID = 0							# Our Request / Response ID that must be in all requests and initiated by us
        self.SessionID = 0					# Session ID will be returned after successful login
        self.header = None

        self.instance_serviceDB = {}		# Store of Object, ProcID, SID, etc.. for 'service'
        self.multicall_query_args = []		# Used with system.multicall method
        self.multicall_query = []			# Used with system.multicall method
        self.multicall_return_check = None  # Used with system.multicall method

        self.fuzzDB = {}					# Used when fuzzing some calls

        self.RestoreEventHandler = {}		# Cache of temporary enabled events

        self.params_tmp = {}					# Used in instance_create()
        self.attachParamsTMP = []			# Used in instance_create()

        self.RemoteServicesCache = {}		# Cache of remote services, used to check if certain service exist or not
        self.RemoteMethodsCache = {}		# Cache of used remote methods
        self.RemoteConfigCache = {}			# Cache of remote config

        self.rhost = None
        self.rport = None
        self.proto = None
        self.events = None
        self.ssl = None
        self.relay_host = None
        self.timeout = None
        self.udp_server = None

        self.proto = None
        self.relay = None
        self.remote = None

        self.debug = None
        self.debugCalls = None				# Some internal debugging

        self.event = threading.Event()
        self.socket_event = threading.Event()
        self.lock = threading.Lock()
        self.recv_stream_status = threading.Event()
        self.terminate = False

    #############################################################################################################
    #
    # Custom pwntools functions
    #
    #############################################################################################################

    def custom_can_recv(self, timeout=0.020):
        """
        wrapper for pwntools 'can_recv()'
        SSLSocket and paramiko recv() do not support any flags
        """

        time.sleep(timeout)

        try:
            """ pwntools """
            if self.remote.can_recv():
                return True
            return False
        except TypeError:
            """ paramiko ssh """
            if self.remote.sock.recv_ready():
                return True
            return False
        except ValueError:
            """ SSL """
            # TODO: Not found any way for SSL
            return True
        except AttributeError:
            """ OSError """
            print('AttributeError')
            return False

    def custom_connect_remote(self, rhost, rport, timeout=10):
        """ Custom SSH connect_remote(), still we using pwntools 'transport()' """
        # channel = self.relay.transport.Channel(timeout=timeout)
        channel = self.relay.transport.open_channel('direct-tcpip', (rhost, rport), ('127.0.0.1', 0), timeout=timeout)
        print(self.relay.transport.is_active())
        return channel

    def custom_exec_command(self, cmd, script='', timeout=10, env_export=None):
        """ Custom SSH exec_command(), still using pwntools 'transport()' """

        env_export = ';'.join('export {}={}'.format(var, env_export.get(var)) for var in env_export)
        cmd = ''.join([env_export, cmd, script])

        stdout = b''
        stderr = b''
        sftp = None
        relay = None

        """
        Generally not many embedded devices who has sftp support,
        meaning it will most likely not support exec_command() and/or python either.
        Just to avoid potential 'psh' hanging in embedded devices
        """
        try:
            sftp = self.relay.transport.open_session(timeout=timeout)
            sftp.settimeout(timeout=timeout)
            sftp.invoke_subsystem('sftp')
        except Exception as e:
            print('[custom_exec_command] (sftp)', repr(e))
            return {"stdout": [], "stderr": ['embedded devices not supported']}
        finally:
            if sftp:
                sftp.close()

        try:
            relay = self.relay.transport.open_session(timeout=timeout)
            relay.settimeout(timeout=timeout)
            relay.exec_command(cmd)

            while True:
                stdout = b''.join([stdout, relay.recv(4096)])
                if relay.exit_status_ready():
                    break
            """ Catch potential stderr from remote """
            stderr = b''.join([stderr, relay.recv_stderr(4096)])
        except Exception as e:
            print('[custom_exec_command] (relay)', repr(e))
            return {"stdout": [], "stderr": ['exec request failed on channel {}'.format(relay.get_id())]}
        finally:
            if relay:
                relay.close()

        stdout = stdout.decode('utf-8').split('\n')
        stderr = stderr.decode('utf-8').split('\n')

        """ return output in list, remove potential empty entries """
        return {
            "stdout": [x for x in stdout if x],
            "stderr": [x for x in stderr if x]
        }

    def dh_discover(self, msg):
        """ Device DHIP/DVRIP discover function """

        cmd = msg.split()
        dh_data = None
        host = None
        sock = None
        remote_recvfrom = None
        remote_ip = None
        remote_port = None

        usage = {
            "dhip": "[host]",
            "dvrip": "[host]"
        }
        if len(cmd) < 2 or len(cmd) > 3 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True
        discover = cmd[1]

        if discover == 'dhip':
            if len(cmd) == 2:
                dip = '239.255.255.251'
            else:
                dip = check_host(cmd[2])
                if not dip:
                    log.failure("Invalid RHOST")
                    return False
            dport = 37810

            query_args = {
                "method": "DHDiscover.search",
                # "method": "deviceDiscovery.refresh",
                # "method": "deviceDiscovery.ipScan",
                # "method": "DHDiscover.setConfig",
                # "method": "Security.getEncryptInfo",
                # "method": "DevInit.account",
                # "method": "PasswdFind.getDescript",
                # "method": "PasswdFind.resetPassword",
                # "method": "PasswdFind.checkAuthCode",
                # "method": "DevInit.leAction",
                # "method": "userManager.getCaps",
                # "method": "DevInit.access",
                # "method": "Security.modifyPwdOutSession",
                "params": {
                    "mac": "",
                    "uni": 1
                },
            }

            header = \
                p64(0x2000000044484950, endian='big') + p64(0x0) + p32(len(json.dumps(query_args))) + \
                p32(0x0) + p32(len(json.dumps(query_args))) + p32(0x0)

            packet = header + json.dumps(query_args).encode('latin-1')

        elif discover == 'dvrip':
            if len(cmd) == 2:
                dip = '255.255.255.255'
            else:
                dip = check_host(cmd[2])
                if not dip:
                    log.failure("Invalid RHOST")
                    return False
            dport = 5050

            packet = p32(0xa3010001, endian='big') + (p32(0x0) * 3) + p32(0x02000000, endian='big') + (p32(0x0) * 3)

        else:
            log.failure('{}'.format(help_all(msg=cmd[0], usage=usage)))
            return False

        if self.relay_host:
            script = r"""
import os, sys, socket, base64

socket.setdefaulttimeout(4)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.sendto(base64.b64decode(os.getenv('PACKET')), (os.getenv('dip'),int(os.getenv('dport'))))

while True:
    try:
        dh_data, addr = sock.recvfrom(8196)
        print({"host": addr[0],
            "dh_data": base64.b64encode(dh_data)
        })
    except Exception as e:
        # sys.stderr.write(repr(e))
        break
sock.close()
"""
            env_export = {
                'PATH': '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin',
                'PACKET': b64e(packet),
                'dip': dip,
                'dport': str(dport)
            }

            if not self.relay:
                dh_data = init_relay(relay=self.relay_host, rhost=self.rhost, rport=self.rport, discover=discover)
                if not dh_data:
                    return False
                self.relay = dh_data.get('dh_relay')

            remote_recvfrom = self.custom_exec_command(
                cmd=';python -c ', script=sh_string(script), env_export=env_export)
        else:
            socket.setdefaulttimeout(3)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            self._debug("SEND", packet)
            sock.sendto(packet, (dip, dport))

        while True:
            if self.relay:

                for host in remote_recvfrom.get('stdout'):
                    x = ast.literal_eval(host)

                    dh_data = b64d(x.get('dh_data'))
                    remote_ip = x.get('host')
                    remote_port = dport
                    break
                if len(remote_recvfrom.get('stdout')):
                    remote_recvfrom.get('stdout').remove(host)
                else:
                    if len(remote_recvfrom.get('stderr')):
                        for stderr in remote_recvfrom.get('stderr'):
                            log.warning('[stderr] {}'.format(stderr))
                    return True
            else:
                try:
                    dh_data, addr = sock.recvfrom(4096)
                    remote_ip = addr[0]
                    remote_port = addr[1]
                except (Exception, KeyboardInterrupt, SystemExit):
                    sock.close()
                    return True

            log.success("dh_discover response from: {}:{}".format(remote_ip, remote_port))
            self._debug("RECV", dh_data)

            dh_data = dh_data[32:].decode('latin-1')

            if discover == 'dhip':
                dh_data = json.loads(dh_data.strip('\x00'))
                print(json.dumps(dh_data, indent=4))

            elif discover == 'dvrip':
                bin_info = {
                    "Version": {
                        "Version": "{}.{}.{}.{}".format(
                            u16(dh_data[0:2]), u16(dh_data[2:4]), u16(dh_data[4:6]), u16(dh_data[6:8]))
                    },
                    "Network": {
                        "Hostname": dh_data[8:24].strip('\x00'),
                        "IPAddress": unbinary_ip(dh_data[24:28]),
                        "SubnetMask": unbinary_ip(dh_data[28:32]),
                        "DefaultGateway": unbinary_ip(dh_data[32:36]),
                        "DnsServers": unbinary_ip(dh_data[36:40]),
                    },
                    "AlarmServer": {
                        "Address": unbinary_ip(dh_data[40:44]),
                        "Port": u16(dh_data[44:46]),
                        "Unknown46-47": u8(dh_data[46:47]),
                        "Unknown47-48": u8(dh_data[47:48]),
                    },
                    "Email": {
                        "Address": unbinary_ip(dh_data[48:52]),
                        "Port": u16(dh_data[52:54]),
                        "Unknown54-55": u8(dh_data[54:55]),
                        "Unknown55-56": u8(dh_data[55:56]),
                    },
                    "Unknown": {
                        "Unknown56-50": unbinary_ip(dh_data[56:60]),
                        "Unknown60-62": u16(dh_data[60:62]),
                        "Unknown82-86": unbinary_ip(dh_data[82:86]),
                        "Unknown86-88": u16(dh_data[86:88]),
                    },
                    "Web": {
                        "Port": u16(dh_data[62:64]),
                    },
                    "HTTPS": {
                        "Port": u16(dh_data[64:66]),
                    },
                    "DVRIP": {
                        "TCPPort": u16(dh_data[66:68]),
                        "MaxConnections": u16(dh_data[68:70]),
                        "SSLPort": u16(dh_data[70:72]),
                        "UDPPort": u16(dh_data[72:74]),
                        "Unknown74-75": u8(dh_data[74:75]),
                        "Unknown75-76": u8(dh_data[75:76]),
                        "MCASTAddress": unbinary_ip(dh_data[76:80]),
                        "MCASTPort": u16(dh_data[80:82]),
                    },

                }

                log.info("Binary:\n{}".format(json.dumps(bin_info, indent=4)))
                log.info("Ascii:\n{}".format(dh_data[88:].strip('\x00')))

    def dh_connect(self, username=None, password=None, logon=None, force=False):
        """ Initiate connection to device and handle possible calls from cmd line """
        console = None

        log.info(
            color('logon type "{}" with proto "{}" at {}:{}'.format(logon, self.proto, self.rhost, self.rport), LGREEN)
        )

        if self.relay_host:
            dh_data = init_relay(relay=self.relay_host, rhost=self.rhost, rport=self.rport)
            if not dh_data:
                return False
            self.relay = dh_data.get('dh_relay')
            self.remote = dh_data.get('dh_remote')

        elif self.proto == 'http' or self.proto == 'https':
            self.remote = DahuaHttp(self.rhost, self.rport, proto=self.proto, timeout=self.timeout)

        else:
            try:
                self.remote = remote(self.rhost, self.rport, ssl=self.ssl, timeout=self.timeout)
            except PwnlibException:
                return False

        if self.args.test:
            self.header = self.proto_header()
            return True

        if not self.args.dump:
            console = log.progress(color('Dahua Debug Console', YELLOW))
            console.status(color('Trying', YELLOW))

        if self.proto == 'dvrip' or self.proto == '3des':
            if not self.dahua_dvrip_login(username=username, password=password, logon=logon):
                if not self.args.dump:
                    if self.args.save:
                        console.success('Save host')
                    else:
                        console.failure(color("Failed", RED))
                    return False
                else:
                    return False

        elif self.proto == 'dhip' or self.proto == 'http' or self.proto == 'https':
            if not self.dahua_dhip_login(username=username, password=password, logon=logon, force=force):

                if not self.args.dump:
                    if self.args.save:
                        console.success('Save host')
                    else:
                        console.failure(color('Failed', RED))
                    return False
                else:
                    return False

        # Old devices fail and close connection
        if logon != 'old_3des':
            query_args = {
                "method": "userManager.getActiveUserInfoAll",
                "params": {
                },
            }

            dh_data = self.send_call(query_args)

            users = '{}'.format(help_msg('Active Users'))
            if dh_data.get('params').get('users') is not None:
                for user in dh_data.get('params').get('users'):
                    users += '{}@{} since {} with "{}" (Id: {}) \n'.format(
                        user.get('Name'),
                        user.get('ClientAddress'),
                        user.get('LoginTime'),
                        user.get('ClientType'),
                        user.get('Id'))
            else:
                users += 'None'
            log.info(users)

            query_args = {
                "method": "magicBox.getDeviceType",
                "params": None,
            }
            self.send_call(query_args, multicall=True)

            """ Classes: NVR, IPC, VTO, VTH, DVR... etc. """
            query_args = {
                "method": "magicBox.getDeviceClass",
                "params": None,
            }
            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "global.getCurrentTime",
                "params": None,
            }
            dh_data = self.send_call(query_args, multicall=True, multicallsend=True)

            self.DeviceClass = \
                dh_data.get('magicBox.getDeviceClass').get('params').get('type') \
                if dh_data and dh_data.get('magicBox.getDeviceClass').get('result') else '(null)'
            self.DeviceType = \
                dh_data.get('magicBox.getDeviceType').get('params').get('type')\
                if dh_data and dh_data.get('magicBox.getDeviceType').get('result') else '(null)'
            if dh_data and dh_data.get('global.getCurrentTime').get('params'):
                remote_time = dh_data.get('global.getCurrentTime').get('params').get('time')
            elif dh_data and dh_data.get('global.getCurrentTime').get('result'):
                remote_time = dh_data.get('global.getCurrentTime').get('result')
            else:
                remote_time = '(null)'

            log.info("Remote Model: {}, Class: {}, Time: {}".format(
                self.DeviceType,
                self.DeviceClass,
                remote_time
            ))

        if self.args.dump:
            return True

        if not self.instance_service('console', dattach=True, start=True):
            console.failure(color("Attach Console failed, using local only", LRED))
            self.console_attach = False
        else:
            self.console_attach = True
            console.success(color('Success', GREEN))

        if self.events:
            self.event_manager(msg='events 1')

        if self.proto in ['http', 'https']:
            _thread.start_new_thread(self.subscribe_notify, ())

        return True

    def _sleep_check_socket(self, delay):
        """ This function will act as the delay for keepAlive of the connection

        At same time it will check and process any late incoming packets every second,
        which will end up in clientNotifyData()
        """
        keep_alive = 0
        dsleep = 1
        dh_data = None

        while True:
            if delay <= keep_alive:
                break
            else:
                keep_alive += dsleep
                if self.terminate:
                    break
                # If received dh_data and not another process locked p2p(), should be callback, break
                if self.custom_can_recv() and not self.lock.locked():
                    try:
                        dh_data = self.p2p(packet=None, recv=True)
                        if not dh_data:
                            continue
                        """ Will always return list """
                        dh_data = fix_json(dh_data)
                        for NUM in range(0, len(dh_data)):
                            self._check_for_keepalive(dh_data[NUM])
                    except EOFError as e:
                        log.failure('[_sleep_check_socket] {}'.format(repr(e)))
                        self.remote.close()
                        return False
                    except (AttributeError, ValueError, TypeError) as e:
                        log.failure('[_sleep_check_socket] ({}) {}'.format(repr(e), dh_data))
                        pass
                time.sleep(dsleep)
                continue

    def _p2p_keepalive(self, delay):
        """ Main keepAlive thread """

        keep_alive = log.progress(color('keepAlive thread', YELLOW))
        keep_alive.success(color('Started', GREEN))

        self.keep_alive_timeout_times = 5
        self.keep_alive_timeout = 0

        while True:
            self._sleep_check_socket(delay)

            if self.terminate:
                return False

            if not self.remote.connected() or self.keep_alive_timeout == self.keep_alive_timeout_times:
                log.warning('self termination ({})'.format(self.rhost))
                self.terminate = True
                self.remote.close()
                # TEST
                # del self.remote
                if self.relay:
                    self.relay.close()
                    # TEST
                    # del self.relay
                return False

            query_args = {
                "method": "global.keepAlive",
                "params": {
                    "timeout": delay,
                    "active": True
                },
            }

            try:
                dh_data = self.p2p(query_args, timeout=10)
            # print('[keepAlive] sending/receiving', dh_data)
            except requests.exceptions.RequestException:
                self.keep_alive_timeout = self.keep_alive_timeout_times
                self.event.set()
                self.remote.close()
                # TEST
                # del self.remote
                if self.relay:
                    self.relay.close()
                    # TEST
                    # del self.relay
                continue

            except EOFError as e:
                log.failure('[keepAlive] {}'.format(repr(e)))
                self.remote.close()
                if self.relay:
                    self.relay.close()
                continue

            if dh_data is None:
                log.failure('[keepAlive timeout] ({})'.format(self.rhost))
                self.keep_alive_timeout += 1
                self.event.set()
                continue

            """ Will always return list """
            dh_data = fix_json(dh_data)
            for NUM in range(0, len(dh_data)):
                self._check_for_keepalive(dh_data[NUM])

    def _check_for_keepalive(self, dh_data):
        try:
            # keepAlive answer
            if dh_data.get('result') and dh_data.get('params').get('timeout'):
                if self.event.is_set():
                    log.success('[keepAlive back] ({})'.format(self.rhost))
                    self.keep_alive_timeout = 0
                    self.event.clear()
            elif not dh_data.get('result') and dh_data.get('error').get('code') == 287637505:
                # Invalid session in request data!
                log.failure('[keepAlive timeout] ({})'.format(self.rhost))
                self.keep_alive_timeout = self.keep_alive_timeout_times
                self.event.set()

            else:
                """
                Not keepAlive answer, send it away to clientNotify
                check for 'client.' callback 'method' or other stuff
                """
                if dh_data:
                    self.client_notify(json.dumps(dh_data))
        except AttributeError:
            if dh_data:
                self.client_notify(json.dumps(dh_data))
            pass

    #
    # Any late dh_data processed from the '_p2p_keepalive()' thread coming from remote device will end up here,
    # sort out with "client.notify....." callback
    #
    def client_notify(self, dh_data):
        #
        # Some stuff prints sometimes 'garbage', like 'dvrip -l'
        #
        dh_data = ndjson.loads(dh_data, strict=False)

        for NUM in range(0, len(dh_data)):
            dh_data = dh_data[NUM]

            if dh_data.get('method') == 'client.notifyConsoleResult':
                return self.console_result(msg=dh_data, callback=True)

            elif dh_data.get('method') == 'client.notifyConsoleAsyncResult':
                return self.console_result(msg=dh_data, callback=True)

            elif dh_data.get('method') == 'client.notifyDeviceInfo':
                return self.device_discovery(msg=dh_data, callback=True)

            elif dh_data.get('method') == 'client.notifyEventStream':

                if self.udp_server:
                    dh_data['host'] = self.rhost

                    #
                    # wifi also need events
                    #
                    # print('[2] netApp')
                    # self.net_app(dh_data,callback=True)
                    #
                    # Send off to main event handler
                    #
                    notify_event = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                    notify_event.sendto(json.dumps(dh_data).encode('latin-1'), ("127.0.0.1", EventInServerPort))
                    notify_event.close()
            else:
                try:
                    if dh_data.get('method'):
                        log.failure(color("[clientNotify] Unhandled callback: {}".format(dh_data.get('method')), RED))
                        print(json.dumps(dh_data, indent=4))

                except AttributeError:
                    log.failure('[clientNotify] Unknown dh_data: {}'.format(dh_data))
                    pass

            return True

    def send_call(self, query_args=None, multicall=False, multicallsend=False, errorcodes=False, login=False):
        """ Primary function for sending/receiving data """

        if query_args is None:
            query_args = ''

        """ Single call """
        if not multicall and not len(self.multicall_query_args):
            """ Just to make 'params' consistent both if it is 'None' or '{}' """
            if len(query_args) and query_args.get('params') is not None:
                if not len(query_args.get('params')):
                    query_args.update({"params": None})

            try:
                dh_data = self.p2p(query_args, login=login)
            except (KeyboardInterrupt, EOFError):
                return None

            if not dh_data:
                return None

            """
            Replicating how Dahua sending dh_data, so we pass on received dh_data with 'transfer'

            packet + split('\n')
            [JSON][0]
            [DATA][1]
            """
            try:
                dh_data = json.loads(dh_data)
            except (AttributeError, JSONDecodeError) as e:
                if not dh_data.find('\n'):
                    log.failure("[sendCall] (json) ({}) {}".format(repr(e), dh_data))
                    pass
                tmp = dh_data.split('\n')
                dh_data = json.loads(tmp[0])
                dh_data.update({"transfer": b64e(tmp[1])})
                pass

            if not dh_data.get('result') and dh_data.get('error'):
                if self.debugCalls:
                    log.failure(color("query: {}".format(query_args), GREEN))
                    log.failure(color(
                        "response: {}".format(dh_data), LRED))

                if errorcodes:
                    return dh_data
                else:
                    return False

            return dh_data

        """ Multi call """
        if not len(self.multicall_query_args):
            self.multicall_query_args = []
            self.multicall_return_check = []

        """
        Normally we will return JSON dh_data with key as the 'method' name when 'params' is None
        Others we will use 'params' name, as the 'method' name can be the same for different calls
        """
        # TODO: For now we need to specify known calls, should be bit smarter to handle all kind of methods
        # (maybe by using ID)
        #

        # Just to make 'params' consistent both if it is 'None' or '{}'
        if len(query_args) and query_args.get('params') is not None:
            if not len(query_args.get('params')):
                query_args.update({"params": None})

        if isinstance(query_args, dict):
            query_args.update({
                'id': self.ID,
                'session': self.SessionID
            })
            self.update_id()

        if len(query_args):
            if query_args.get('params') is None:
                method = query_args.get('method')
            elif query_args.get('method') == 'configManager.getConfig' and query_args.get('params').get('name'):
                method = query_args.get('params').get('name')
            elif query_args.get('method') == 'configManager.setConfig' and query_args.get('params').get('name'):
                method = query_args.get('params').get('name')
            elif query_args.get('method') == 'configManager.getDefault' and query_args.get('params').get('name'):
                method = query_args.get('params').get('name')
            elif query_args.get('method').split('.')[0] == 'netApp':
                method = query_args.get('method')

            # TODO: Very beta test
            elif query_args.get('id'):
                method = query_args.get('id')

            else:
                log.failure("[sendCall] (multicall): {}".format(query_args.get('method')))
                return False

            self.multicall_query_args.append(query_args)
            self.multicall_return_check.append({"id": query_args.get('id'), "method": method})

            # TODO: Not good idea to have one additional outside of P2P, but is needed (for now)
            # self.ID += 1

        if multicall and multicallsend and len(self.multicall_query_args):
            self.multicall_query = {
                "method": "system.multicall",
                "params": self.multicall_query_args,
            }

            try:
                dh_data = self.p2p(self.multicall_query)
            except (KeyboardInterrupt, EOFError):
                self.multicall_query_args = []
                self.multicall_return_check = []
                return None

            if not dh_data or not len(dh_data):
                print('[system.multicall] data:', dh_data)
                if self.debugCalls:
                    log.failure(color("[sendCall #1] No dh_data back with query: (system.multicall)", LRED))
                # Lets listen again, keepAlive might got it and sent back to recv()
                try:
                    dh_data = self.p2p(packet=None, recv=True)
                except (KeyboardInterrupt, EOFError):
                    if self.debugCalls:
                        log.failure(color("[sendCall #2] No dh_data back with query: (system.multicall)", LRED))
                    self.multicall_query_args = []
                    self.multicall_return_check = []
                    return None
                if not dh_data:
                    return None

            try:
                dh_data = json.loads(dh_data)
            except (AttributeError, JSONDecodeError) as e:
                log.failure("[sendCall] (json) ({}) {}".format(repr(e), dh_data))
                try:
                    dh_data += self.p2p(packet=None, recv=True)
                except (KeyboardInterrupt, EOFError):
                    self.multicall_query_args = []
                    self.multicall_return_check = []
                    return None

                if not dh_data:
                    return None

            if not dh_data.get('result'):
                if self.debugCalls:
                    log.failure(color("query: {}".format(self.multicall_query_args), GREEN))
                    log.failure(color(
                        "response: {}".format(dh_data), LRED))
                return None

            dh_data = dh_data.get('params')
            tmp = {}

            for key in range(0, len(dh_data)):
                """ Looks like to be FIFO, bailout just in case to catch any ID mismatch """
                if not self.multicall_return_check[key].get('id') == dh_data[key].get('id'):
                    log.error("Function SendCall() ID mismatch :\nreq: {}\nres: {}".format(
                        self.multicall_return_check[key], dh_data[key]))
                tmp[self.multicall_return_check[key].get('method')] = dh_data[key]

            self.multicall_query_args = []
            self.multicall_return_check = None
            return tmp

    def instance_service(
            self, method_name='', dattach=False, params=None, attach_params=None,
            stop=False, start=False, pull=None, clean=False, list_all=False, fuzz=False,
            attach_only=False, multicall=False, multicallsend=False):
        """
        Main function to create remote instance and attach (if needed)
        Storing all details in 'self.instance_serviceDB', simplifies to create/check/pull/close remote instance
        """

        if clean:
            for service in copy.deepcopy(self.instance_serviceDB):
                if not service == 'console':
                    log.warning(
                        color('BUG: instance_service "{}" should have already been stopped (stop now)'.format(service),
                              LRED))
                if self.debugCalls:
                    log.info('[instance_service] sending stop to: {}'.format(service))
                self.instance_service(service, stop=True)
            return True

        elif list_all:
            for service in self.instance_serviceDB:
                dh_data = '{}'.format(help_msg(service))
                for key in self.instance_serviceDB.get(service):
                    dh_data += '[{}] = {}\n'.format(key, self.instance_serviceDB.get(service).get(key))
                log.info(dh_data)
            return True

        elif pull:
            if method_name not in self.instance_serviceDB:
                if self.debugCalls:
                    log.failure('[instanceService] (pull) method_name: {} do not exist'.format(method_name))
                return False
            if self.debugCalls:
                log.success('[instanceService] (pull) method_name: {} do exist'.format(method_name))
            return self.instance_serviceDB.get(method_name).get(pull)

        elif start:
            if not self.check_for_service(method_name):
                if self.debugCalls:
                    log.failure('[instanceService] (service) method_name: {} do not exist'.format(method_name))
                return False
            if method_name in self.instance_serviceDB:
                if self.debugCalls:
                    log.failure('[instanceService] (create) method_name: {} do exist'.format(method_name))
                return False

            object_id, _proc_id, _sid, dparams, attach_params = self.instance_create(
                method=method_name,
                dattach=True if attach_params else dattach,
                params=params,
                attach_params=attach_params,
                fuzz=fuzz,
                attach_only=attach_only,
                multicall=multicall,
                multicallsend=multicallsend,
            )

            if multicall and not multicallsend:
                return

            """ More for when fuzzing, we want the Response and not only True/False """
            if fuzz and _sid or fuzz and object_id:
                self.fuzzDB.update({
                    method_name: {
                        "method_name": method_name,
                        "attach": True if attach_params else dattach,
                        "params": dparams,
                        "attach_params": attach_params,
                        "object": object_id,		# False if failure
                        "proc": _proc_id,		# method_name
                        "sid": _sid 			# Response dh_data w/ error code
                    }
                })

            if not object_id:
                if self.debugCalls:
                    log.failure('[instanceService] (create) Object: {} do not exist'.format(method_name))
                return False

            self.instance_serviceDB.update({
                method_name: {
                    "method_name": method_name,
                    "attach": True if attach_params else dattach,
                    "params": dparams,
                    "attach_params": attach_params,
                    "object": object_id,
                    "proc": _proc_id,
                    "sid": _sid
                }
            })

            if self.debugCalls:
                log.success('[instanceService] (update) {}'.format(method_name))
                self.instance_service(list_all=True)
            return True

        elif stop:
            if method_name not in self.instance_serviceDB:
                if self.debugCalls:
                    log.failure('[instanceService] (destroy) method_name: {} do not exist'.format(method_name))
                return False

            result, method, dh_data = self.instance_destroy(
                method=method_name,
                _proc_id=self.instance_serviceDB.get(method_name).get('proc'),
                object_id=self.instance_serviceDB.get(method_name).get('object'),
                detach=self.instance_serviceDB.get(method_name).get('attach'),
                detach_params=self.instance_serviceDB.get(method_name).get('attach_params')
            )
            if method_name in self.instance_serviceDB:
                self.instance_serviceDB.pop(method_name)
                if self.debugCalls:
                    log.success('[destroy] pop: {}'.format(method_name))
                    self.instance_service(list_all=True)

            if not result:
                if self.debugCalls:
                    log.failure('[instanceService] (destroy,instance_destroy) {} {} {}'.format(result, method, dh_data))
                return False

        return True

    def instance_create(
            self, method, dattach=True, params=None, attach_params=None, fuzz=False, attach_only=False,
            multicall=False, multicallsend=False):
        """ Create factory.instance """
        object_id = None
        _proc_id = None
        dparams = None
        answer = None

        if not attach_only:
            query_args = {
                "method": "{}.factory.instance".format(method),
                "params": params,
            }

            if attach_params:
                self.attachParamsTMP.append(attach_params)
            if params:
                self.params_tmp.update({query_args.get('id'): params})

            dh_data = self.send_call(query_args, errorcodes=fuzz, multicall=multicall, multicallsend=multicallsend)

            if multicall and not multicallsend:
                return None, None, None, None, None

            if dh_data is False:
                return False, "{}.factory.instance".format(method), dh_data, params, None

            if multicall and multicallsend:
                for answer in dh_data:
                    if dh_data.get(answer).get('result'):
                        break
                dh_data = dh_data.get(answer)
                dparams = self.params_tmp.get(dh_data.get('id'), 'error to get "params"')

            if dh_data is None or not dh_data.get('result'):
                return False, "{}.factory.instance".format(method), dh_data, params, None

            object_id = dh_data.get('result')
            _proc_id = object_id

            if not dattach:
                self.params_tmp = {}
                self.attachParamsTMP = []
                # print('[instance_create] No attach')
                return object_id, _proc_id, None, params if not multicall else dparams, None

        if attach_only:
            object_id = attach_only
            _proc_id = attach_only

        if multicall and multicallsend:

            attach_id = {}

            for paramsTmp in self.attachParamsTMP:
                query_args = {
                    # "method": "{}.attachAsyncResult".format(method),	# .params.cmd needed
                    "method": "{}.attach".format(method),
                    "params": {
                        "proc": _proc_id,
                        # "cmd": "????",	# .attachAsyncResult
                    },
                    "object": object_id,
                }

                query_args.get('params').update(paramsTmp)
                attach_id.update({query_args.get('id'): paramsTmp})

                self.send_call(query_args, errorcodes=fuzz, multicall=True, multicallsend=False)

            query_args = {
                # "method": "{}.attachAsyncResult".format(method),	# .params.cmd needed
                "method": "{}.attach".format(method),
                "params": {
                    "proc": _proc_id,
                    # "cmd": "????",	# .attachAsyncResult
                },
                "object": object_id,
            }

            dh_data = self.send_call(query_args, errorcodes=fuzz, multicall=True, multicallsend=True)
            if not dh_data:
                self.instance_destroy(method=method, _proc_id=_proc_id, object_id=object_id, detach=False)
                return False, "{}.attach".format(method), dh_data, dparams, attach_params

            for answer in dh_data:
                if dh_data.get(answer).get('result'):
                    break
            dh_data = dh_data.get(answer)
            attach_params = attach_id.get(dh_data.get('id'), 'error to get "attach_params"')

        else:
            query_args = {
                # "method": "{}.attachAsyncResult".format(method),	# .params.cmd needed
                "method": "{}.attach".format(method),
                "params": {
                    "proc": _proc_id,
                    # "cmd": "????",	# .attachAsyncResult
                },
                "object": object_id,
            }

            if attach_params:
                query_args.get('params').update(attach_params)
            dh_data = self.send_call(query_args, errorcodes=fuzz, multicall=multicall, multicallsend=multicallsend)

        if not dh_data and not attach_only:
            self.instance_destroy(method=method, _proc_id=_proc_id, object_id=object_id, detach=False)
            return False, "{}.attach".format(method), dh_data, params if not multicall else dparams, attach_params

        if not dh_data.get('result'):
            if object_id and not attach_only:
                self.instance_destroy(method=method, _proc_id=_proc_id, object_id=object_id, detach=False)
            return False, "{}.attach".format(method), dh_data, params if not multicall else dparams, attach_params

        if dh_data.get('params'):
            _sid = dh_data.get('params').get('SID')
        else:
            _sid = None

        self.params_tmp = {}
        self.attachParamsTMP = []
        return object_id, _proc_id, _sid, params if not multicall else dparams, attach_params

    def instance_destroy(self, method, _proc_id, object_id, detach=True, detach_params=None):
        """ Destroy factory.instance """

        if detach:
            query_args = {
                # "method": "{}.detachAsyncResult".format(method),	# .params.cmd needed
                "method": "{}.detach".format(method),
                "params": {
                    "proc": _proc_id,
                    # "cmd": "????",	# .detachAsyncResult
                },
                "object": object_id,
            }
            if detach and detach_params:
                query_args.get('params').update(detach_params)

            dh_data = self.send_call(query_args)
            # if dh_data == False or not dh_data:
            if not dh_data:
                return False, "{}.detach".format(method), dh_data

            if not dh_data.get('result'):
                return False, "{}.detach".format(method), dh_data

        query_args = {
            "method": "{}.destroy".format(method),
            "params": None,
            "object": object_id,
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            return False, "{}.destroy".format(method), dh_data

        if not dh_data.get('result'):
            return False, "{}.destroy".format(method), dh_data

        return True, "{}.destroy".format(method), dh_data

    #
    # Checking and caches if a service exist or not
    #
    def check_for_service(self, service):

        query_args = {
            "method": "system.listService",
            "params": None,
        }
        if not len(self.RemoteServicesCache):
            self.RemoteServicesCache = self.send_call(query_args)
            if not self.RemoteServicesCache:
                return False
        if service == 'dump':
            return

        if self.RemoteServicesCache.get('result'):
            for count in range(0, len(self.RemoteServicesCache.get('params').get('service'))):
                if self.RemoteServicesCache.get('params').get('service')[count] == service:
                    return True

        log.failure("Service [{}] not supported on remote device".format(service))
        return False

    #
    # Main function for subscribe on events from device
    #
    def event_manager(self, msg):

        cmd = msg.split()

        usage = {
            "1": "(enable)",
            "0": "(disable)"
        }

        if len(cmd) == 1 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        if not self.udp_server:
            if self.debugCalls:
                log.warning('Local UDP server not running')
            return False

        method_name = 'eventManager'
        codes = ["All"]

        if cmd[1] == '1':

            if self.instance_service(method_name, pull='object'):
                log.failure("eventManager already enabled")
                return False

            self.event_manager_set_config()

            self.instance_service(method_name, attach_params={"codes": codes}, start=True)
            object_id = self.instance_service(method_name, pull='object')
            if not object_id:
                return False

        elif cmd[1] == '0':

            if not self.instance_service(method_name, pull='object'):
                log.failure("eventManager already disabled")
                return False

            self.event_manager_set_config()
            self.instance_service(method_name, stop=True)

            return

        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return False

    #
    # Will dump remote config, scan for EventHandler() and enable disabled ones
    # Using setTemporaryConfig / restoreTemporaryConfig, so changes will not be permanent (in case of reboot)
    #
    def event_manager_set_config(self):

        method_name = 'configManager'

        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        event_id_map = {}

        if not self.instance_service('eventManager', pull='object'):

            if not self.RemoteConfigCache:
                log.info("Caching remote config")
                query_args = {
                    "method": "configManager.getConfig",
                    "params": {
                        "name": 'All',
                    },
                }
                self.RemoteConfigCache = self.send_call(query_args)
                if not self.RemoteConfigCache:
                    return False

            config_members = copy.deepcopy(self.RemoteConfigCache.get('params').get('table'))

            config = {}

            for member in config_members:
                try:

                    if isinstance(config_members[member], list):
                        for count in range(0, len(config_members[member])):

                            if config_members[member][count].get('EventHandler'):

                                if not config_members[member][count].get('Enable'):
                                    self.RestoreEventHandler.update({
                                        member: config_members[member],
                                    })
                                    config.update({member: config_members[member]})
                                    config[member][count]['Enable'] = True

                                    query_args = {
                                        "method": "configManager.setTemporaryConfig",
                                        "params": {
                                            "name": member,
                                            "table": config[member],
                                        },
                                        "object": object_id,
                                        "session": self.SessionID,
                                        "id": self.ID
                                    }
                                    event_id_map.update({self.ID: member})
                                    self.send_call(query_args, multicall=True)
                                elif config_members[member][count].get('Enable'):
                                    log.success('{}[{}]: Already enabled'.format(member, count))

                            elif config_members[member][count].get('CurrentProfile'):  # CommGlobal

                                if not config_members[member][count].get('AlarmEnable')\
                                        or not config_members[member][0].get('ProfileEnable'):
                                    self.RestoreEventHandler.update({
                                        member: config_members[member],
                                    })
                                    config.update({member: config_members[member]})
                                    config[member][count]['AlarmEnable'] = True
                                    config[member][count]['ProfileEnable'] = True

                                    query_args = {
                                        "method": "configManager.setTemporaryConfig",
                                        "params": {
                                            "name": member,
                                            "table": config[member],
                                        },
                                        "object": object_id,
                                        "session": self.SessionID,
                                        "id": self.ID
                                    }
                                    event_id_map.update({self.ID: member})
                                    self.send_call(query_args, multicall=True)
                                elif config_members[member][count].get('AlarmEnable'):
                                    log.success('{}[{}]: Already enabled'.format(member, count))

                    elif isinstance(config_members[member], dict):

                        if 'EventHandler' in config_members[member]:

                            if not config_members[member].get('Enable'):
                                self.RestoreEventHandler.update({member: config_members[member]})
                                config.update({member: config_members[member]})
                                config[member]['Enable'] = True

                                query_args = {
                                    "method": "configManager.setTemporaryConfig",
                                    "params": {
                                        "name": member,
                                        "table": config[member],
                                    },
                                    "object": object_id,
                                    "session": self.SessionID,
                                    "id": self.ID
                                }
                                event_id_map.update({self.ID: member})
                                self.send_call(query_args, multicall=True)
                            elif config_members[member].get('Enable'):
                                log.success('{}: Already enabled'.format(member))

                        elif 'AlarmEnable' in config_members[member]:  # CommGlobal

                            if not config_members[member].get('AlarmEnable')\
                                    or not config_members[member].get('ProfileEnable'):
                                self.RestoreEventHandler.update({member: config_members[member]})
                                config.update({member: config_members[member]})
                                config[member]['AlarmEnable'] = True
                                config[member]['ProfileEnable'] = True

                                query_args = {
                                    "method": "configManager.setTemporaryConfig",
                                    "params": {
                                        "name": member,
                                        "table": config[member],
                                    },
                                    "object": object_id,
                                    "session": self.SessionID,
                                    "id": self.ID
                                }
                                event_id_map.update({self.ID: member})
                                self.send_call(query_args, multicall=True)
                            elif config_members[member].get('AlarmEnable'):
                                log.success('{}: Already enabled'.format(member))

                except (AttributeError, IndexError):
                    pass

            log.info("Enabling disabled events")
            dh_data = self.send_call(None, multicall=True, multicallsend=True)
            for ID in event_id_map:
                if dh_data.get(ID).get('result'):
                    log.success('{}: {}'.format(event_id_map.get(ID), dh_data.get(ID).get('result')))
                else:
                    log.failure('{}: {}'.format(event_id_map.get(ID), dh_data.get(ID).get('result')))
            self.instance_service(method_name, stop=True)
            return True

        elif self.instance_service('eventManager', pull='object'):

            for member in self.RestoreEventHandler:
                query_args = {
                    "method": "configManager.restoreTemporaryConfig",
                    "params": {
                        "name": member,
                    },
                    "object": object_id,
                    "session": self.SessionID,
                    "id": self.ID
                }
                event_id_map.update({query_args.get('id'): member})
                self.send_call(query_args, multicall=True)

        log.info("Restoring event config")
        dh_data = self.send_call(None, multicall=True, multicallsend=True)

        for ID in event_id_map:
            if dh_data.get(ID).get('result'):
                log.success('{}: {}'.format(event_id_map.get(ID), dh_data.get(ID).get('result')))
            else:
                log.failure('{}: {}'.format(event_id_map.get(ID), dh_data.get(ID).get('result')))

        self.instance_service(method_name, stop=True)
        return

    def console_result(self, msg, callback=False):

        #
        # Not sure how this looks like, catch the callback and just dump it to console
        #
        # NVR additional 'console' w/ console.attachAsyncResult, console.detachAsyncResult
        if msg.get('method') == 'client.notifyConsoleAsyncResult':
            log.info("callback: {}".format(msg.get('method')))
            print(callback)
            print(json.dumps(msg, indent=4))
            if self.proto in ['http', 'https']:
                self.recv_stream_status.set()
            return True

        paramsinfo = msg.get('params').get('info')

        if not int(paramsinfo.get('Count')):
            log.warning("(null) dh_data received from Console")
            return False

        for paramscount in range(0, int(paramsinfo.get('Count'))):
            print(str(paramsinfo.get('Data')[paramscount]).strip('\n'))
        if self.proto in ['http', 'https']:
            self.recv_stream_status.set()
        return True

    #
    # Device discovery - by remote device
    #
    def device_discovery(self, msg, callback=False):

        if callback:
            dh_data = msg
            print(json.dumps(dh_data, indent=4))
            return True

        cmd = msg.split()

        usage = {
            "stop": "(stop)",
            "multicast": "(Discover devices with Multicast)",
            "arpscan": {
                "<ipBegin> <ipEnd>": "(Discover devices with ARP)"
            },
            "refresh": "(<Undefined> Not working)",
            "scan": "(<Undefined> Not working)",
            "setconfig": "(<Undefined> Not working)",
        }

        if len(cmd) == 1 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        #
        # for help
        # multicast = 239.255.255.251 UDP/37810 and 255.255.255.255 UDP/5050
        # arpscan = arp ip_begin - ip_end
        #

        method_name = 'deviceDiscovery'

        # if not self.instance_service(method_name,pull='object'):
        # self.instance_service(method_name,attach=True,start=True)
        # object_id = self.instance_service(method_name,fuzz=True,pull='object')
        # if not object_id:
        # log.failure('{}: Error!'.format(method_name))
        # return False

        if cmd[1] == 'stop':

            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.stop",
                "params": None,
                "object": object_id,
            }

            dh_data = self.send_call(query_args)
            if not dh_data:
                return

            if not self.instance_service(method_name, stop=True):
                return False

            return True

        elif cmd[1] == 'multicast':

            if not self.instance_service(method_name, pull='object'):
                self.instance_service(method_name, dattach=True, start=True)
            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.start",
                "params": {
                    "timeout": "15",
                },
                "object": object_id,
            }

        elif cmd[1] == 'arpscan':

            if not len(cmd) == 4:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False
            ip_begin = cmd[2]
            ip_end = cmd[3]

            if not check_ip(cmd[2]):
                log.failure('"{}" is not valid host'.format(cmd[2]))
                return False
            if not check_ip(cmd[3]):
                log.failure('"{}" is not valid host'.format(cmd[3]))
                return False

            if not self.instance_service(method_name, pull='object'):
                self.instance_service(method_name, dattach=True, start=True)
            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.ipScan",
                "params": {
                    "ipBegin": ip_begin,
                    "ipEnd": ip_end,
                    "timeout": "1",
                },
                "object": object_id,
            }

        elif cmd[1] == 'refresh':
            if not self.instance_service(method_name, pull='object'):
                self.instance_service(method_name, dattach=True, start=True)
            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.refresh",
                "params": {
                    "device": None,
                    # "timeout":5,
                    # "device":"eth2",
                    # "object":object_id,
                },
                "object": object_id,
            }

        elif cmd[1] == 'scan':  # (pthread) error: {'code': 268632080, 'message': ''}

            if not self.instance_service(method_name, pull='object'):
                self.instance_service(method_name, dattach=True, start=True)
            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.scanDevice",
                "params": {
                    "ip": ["192.168.5.21"],
                    "timeout": 10,
                },
                "object": object_id,
            }

        elif cmd[1] == 'setconfig':  # not complete
            # {
            # 'Mac': '3c:ef:8c:bf:a2:04',
            # 'Result': True,
            # 'DeviceConfig':
            # {
            # 'IPv4Address':
            # {
            # 'DhcpEnable': True,
            # 'SubnetMask': '255.255.255.0',
            # 'DefaultGateway': '192.168.5.1',
            # 'IPAddressOld': '192.168.5.21',
            # 'IPAddress': '192.168.5.21'
            # }
            # },
            # 'UTC': 1611173991.0,
            # 'LocaleTime':
            # '2021-01-20 22:19:51'
            # }

            if not self.instance_service(method_name, pull='object'):
                self.instance_service(method_name, dattach=True, start=True)
            object_id = self.instance_service(method_name, fuzz=True, pull='object')
            if not object_id:
                log.failure('{}: Error!'.format(method_name))
                return False

            query_args = {
                "method": "deviceDiscovery.setConfig",
                "params": {
                    "mac": "a0:bd:de:ad:be:ef",
                    "username": "admin",
                    "password": "admin",  # shall be encrypted
                    "devConfig": {"DummyConfig": ""},  # Needs to figure right params
                },
                "object": object_id,
            }

        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        dh_data = self.send_call(query_args, errorcodes=True)
        if dh_data.get('result'):
            print(json.dumps(dh_data, indent=4))
        else:
            self.instance_service(method_name, stop=True)
            log.failure('{}: {}'.format(query_args.get('method'), dh_data.get('error')))

        return

    def cleanup(self):
        """ Clean up before we quit, if needed (and can do so) """
        if self.instance_service('eventManager', pull='object'):
            self.event_manager(msg="events 0")
        if self.instance_service('deviceDiscovery', pull='object'):
            self.device_discovery(msg='rdiscover stop')

    def _debug(self, direction, packet):
        """ Traffic debug """
        if self.debug and packet is not None:

            """ Print send/recv dh_data and current line number """
            print(color(
                "[BEGIN {} ({})] <{:-^40}>".format(
                    direction, self.rhost, inspect.currentframe().f_back.f_lineno), LBLUE))
            if (self.debug == 2) or (self.debug == 3):
                print(hexdump(packet))
            if (self.debug == 1) or (self.debug == 3):
                if packet[4:8] == b'DHIP' or dahua_proto(packet[0:2]):

                    if packet[0:2] == p16(0xb300, endian='big'):
                        header = packet[0:120]
                        dh_data = packet[120:]
                    else:
                        header = packet[0:32]
                        dh_data = packet[32:]

                    print("{}|{}|{}|{}|{}|{}|{}|{}".format(
                        binascii.b2a_hex(header[0:4]).decode('latin-1'),
                        binascii.b2a_hex(header[4:8]).decode('latin-1'),
                        binascii.b2a_hex(header[8:12]).decode('latin-1'),
                        binascii.b2a_hex(header[12:16]).decode('latin-1'),
                        binascii.b2a_hex(header[16:20]).decode('latin-1'),
                        binascii.b2a_hex(header[20:24]).decode('latin-1'),
                        binascii.b2a_hex(header[24:28]).decode('latin-1'),
                        binascii.b2a_hex(header[28:32]).decode('latin-1')
                    ))

                    if dh_data:
                        print("{}".format(dh_data.decode('latin-1').strip('\n')))
                elif self.proto in ['http', 'https']:
                    print(packet)
                elif packet:
                    """ Unknown packet, do hexdump """
                    log.failure("DEBUG: Unknown packet")
                    print(hexdump(packet))
            print(color("[ END  {} ({})] <{:-^40}>".format(
                direction, self.rhost, inspect.currentframe().f_back.f_lineno), BLUE))
        return

    def _p2p_len(self, dh_data):

        len_recved = 0
        len_expect = 0

        if self.proto == 'dhip':
            if dh_data[4:8] == b'DHIP':
                len_recved = u32(dh_data[16:20])
                len_expect = u32(dh_data[24:28])
            else:
                print('Not DHIP')
                print(dh_data)
                return None
        elif self.proto == 'dvrip' or self.proto == '3des':
            if dahua_proto(dh_data[0:2]):

                # Field for amount of dh_data in DVRIP/3DES differs
                proto = [
                    b'\xb0\x00',
                    b'\xb0\x01'
                ]
                # DVRIP Login response
                if dh_data[0:2] in proto:
                    len_recved = 0
                    len_expect = u32(dh_data[4:8]) + 32
                else:
                    # DVRIP JSON
                    len_recved = u32(dh_data[4:8])
                    len_expect = u32(dh_data[16:20])
            else:
                print('Not DVRIP')
                print(dh_data)
                return None

        """
        LEN is w/o 32 bytes header
        Make a calculation to find out how many headers we expecting and add to 'len_expect'
        """
        if len_recved:
            if len_expect == len_recved:
                len_expect += 32
            else:
                binary_header = len_expect // len_recved
                if len_recved * binary_header < len_expect:
                    len_expect += (binary_header + 1) * 32
        return len_expect

    def update_id(self):
        if self.ID == 0xffffffff:
            self.ID = 0
        else:
            self.ID += 1

    def p2p(self, packet=None, recv=False, lock=True, timeout=60, login=False):
        """ Handle all external communication to and from device """
        p2p_header = ''
        p2p_query_return = []
        len_recved = 0

        if packet is not None and isinstance(packet, dict) and not packet.get('id'):
            packet.update({
                'id': self.ID,
                'session': self.SessionID
            })

        # TODO
        # Fix bugs with SSH relay
        if self.proto in ['http', 'https']:
            self.lock.acquire()
            self._debug("SEND", '{},{}\n\n{}'.format(self.remote.headers, self.remote.cookies.get_dict(), packet))
            dh_data = self.remote.send(query_args=packet, login=login, timeout=20)
            self.update_id()
            self.lock.release()
            if not dh_data:
                return None
            elif isinstance(dh_data, str):
                return dh_data
            self._debug("RECV", '{}\n\n{}'.format(dh_data.headers, dh_data.json()))
            return dh_data.content

        if lock:
            self.lock.acquire()

        if not recv:
            if packet is None:
                packet = b''

            header = copy.copy(self.header)
            header = header.replace('_SessionHexID_'.encode('latin-1'), p32(self.SessionID))
            header = header.replace('_LEN_'.encode('latin-1'),
                                    p32(len(json.dumps(packet).encode('latin-1'))) if isinstance(packet, dict)
                                    else p32(len(packet))
                                    )
            header = header.replace('_ID_'.encode('latin-1'), p32(self.ID))

            if not len(header) == 32:
                log.error("Binary header != 32 ({})".format(len(header)))
                if self.lock.locked():
                    self.lock.release()
                return None
            self.update_id()

            """
            Replicating how Dahua sending dh_data (not working for upload to device)
            [JSON] + \n + [DATA]
            """
            try:
                if len(packet) and packet.get('transfer'):
                    out = b64d(packet.get('transfer'))
                    packet.pop('transfer')
                    packet = json.dumps(packet) + '\n' + out.decode('latin-1')
                    packet = packet.encode('latin-1')
                elif isinstance(packet, dict):
                    packet = json.dumps(packet).encode('latin-1')
            except (JSONDecodeError, AttributeError):
                pass

            self._debug("SEND", header + packet)

            try:
                if self.relay:
                    if not self.relay.connected():
                        self.remote.close()
                        self.relay.close()
                        if self.lock.locked():
                            self.lock.release()
                        self.socket_event.set()
                        return None

                if not self.remote.connected():
                    log.error("Connection closed")
                    return None
                self.remote.send(header + packet)
            except Exception as e:
                if self.lock.locked():
                    self.lock.release()
                self.socket_event.set()
                log.failure('[p2p] send: {}'.format(repr(e)))
                return None

        #
        # We must expect there is no output from remote device
        # Some debug cmd do not return any output, some will return after timeout/failure, most will return directly
        #
        start = time.time()
        dh_data = b''

        # Checking in binary header for the amount of dh_data to be received
        # while True:
        try:
            # dh_data = self.remote.recv(numb=32, timeout=1)
            while len(dh_data) != 32:
                dh_data = b''.join([dh_data, self.remote.recv(numb=1, timeout=0.5)])
                # print(len(dh_data))
                # Prevent infinite loop
                if time.time() - start > timeout:
                    log.failure('[p2p] timeout (dh_data != 32)')
                    if self.lock.locked():
                        self.lock.release()
                    return None
            # print('end')

            # if len(dh_data):
            len_expect = self._p2p_len(dh_data)
            if not len_expect:
                log.failure('[p2p] Unknown proto')
                return None

            # if len_expect:
            while True:
                dh_data = b''.join([dh_data, self.remote.recv(numb=1024, timeout=0.5)])
                # print('[p2p] LEN', len(dh_data))

                if len(dh_data) == len_expect:
                    break
                elif len(dh_data) > len_expect:
                    len_expect += self._p2p_len(dh_data[len_expect:])
                    continue

                # Prevent infinite loop
                if time.time() - start > timeout:
                    log.failure('[p2p] timeout (dh_data)')
                    if self.lock.locked():
                        self.lock.release()
                    return None
            # break

        except KeyboardInterrupt:
            if self.lock.locked():
                self.lock.release()
            raise KeyboardInterrupt
        except EOFError as e:
            if self.lock.locked():
                self.lock.release()
            self.remote.close()
            log.failure('[p2p] {}'.format(repr(e)))
            raise EOFError

        if not len(dh_data) and self.lock.locked():
            self.lock.release()
            log.failure("[p2p] Nothing received from remote!")
            return None

        while len(dh_data):
            try:
                # DHIP
                if dh_data[4:8] == b'DHIP':
                    p2p_header = dh_data[0:32]
                    len_recved = u32(dh_data[16:20])
                    dh_data = dh_data[32:]
                # DVRIP
                elif dahua_proto(dh_data[0:2]):
                    len_recved = u32(dh_data[4:8])
                    p2p_header = dh_data[0:32]

                    if p2p_header[24:28] == p32(0x0600f900, endian='big'):
                        self.SessionID = u32(p2p_header[16:20])
                        self.AuthCode = p2p_header[28:32]
                        self.ErrorCode = p2p_header[8:12]

                    if len(dh_data) == 32:
                        self._debug("RECV", p2p_header)
                    dh_data = dh_data[32:]
                else:
                    if len_recved == 0:
                        log.failure("[p2p] Unknown packet")
                        print("PROTO: \033[92m[\033[91m{}\033[92m]\033[0m".format(binascii.b2a_hex(dh_data[0:4])))
                        print(hexdump(dh_data))
                        if self.lock.locked():
                            self.lock.release()
                        return None
                    p2p_recved = dh_data[0:len_recved]
                    if len_recved:
                        self._debug("RECV", p2p_header + p2p_recved)
                        try:
                            tmp = json.loads(p2p_recved)
                            if tmp.get('callback'):
                                self.client_notify(json.dumps(tmp))
                                p2p_recved = b''
                        except (ValueError, AttributeError):
                            pass
                    else:
                        self._debug("RECV", p2p_header)
                    if len(p2p_recved):
                        p2p_query_return.append(p2p_recved.decode('latin-1'))
                    dh_data = dh_data[len_recved:]
            except Exception as e:
                print('[p2p] while len(dh_data)', repr(e))
                print(dh_data)
                return None
        """
        We do expect data, get more data if we are about to return empty and more data is available,
        most probably been callback data previously
        """
        return_data = ''.join(map(str, p2p_query_return))
        if not len(return_data) and self.custom_can_recv(0.100):
            """ We need to go back w/o unlocking/locking """
            return_data = self.p2p(recv=True, lock=False)

        if self.lock.locked():
            self.lock.release()
        return return_data

    #
    # DHIP Login function
    #
    def dahua_dhip_login(self, username=None, password=None, logon=None, force=False):

        login = log.progress(color('Login', YELLOW))

        pwd_manager = PwdManager()

        self.header = self.proto_header()

        query_args = {
            "method": "global.login",
            "params": {
            },
        }
        params = pwd_manager.dhip(
            rhost=self.rhost,
            query_args=query_args,
            username=username,
            password=password,
            login=login,
            logon=logon,
            force=force
        )
        if not params:
            return False

        if self.ssl:
            params.update({"Encryption": "SSL"})

        """
        if self.args.logon == 'local':
            query_args.update({"id": 1111111})
            query_args.update({"session": 2222222})
        """
        query_args.get('params').update(params)
        dh_data = self.send_call(query_args, errorcodes=True, login=True)

        if not dh_data:
            login.failure("global.login [random]")
            return False

        if dh_data.get('result'):
            login.success(color('Success', GREEN))
            self.SessionID = dh_data.get('session')
            dh_realm = None

            if self.args.save:
                pwd_manager.save_host(
                    rhost=self.rhost,
                    rport=self.rport,
                    proto=self.proto,
                    username=username,
                    password=password,
                    dh_realm=dh_realm,
                    relay=self.args.relay,
                    events=self.events,
                    logon=logon
                )
                return False

            if not self.args.dump:
                keep_alive = dh_data.get('params').get('keepAliveInterval')
                _thread.start_new_thread(self._p2p_keepalive, (keep_alive,))

            return True

        if dh_data.get('error').get('code') not in [268632079, 401]:  # Login Challenge
            login.failure("global.login {}".format(dh_data.get('error')))
            return False

        self.SessionID = dh_data.get('session')
        dh_realm = dh_data.get('params').get('realm')

        if logon == 'onvif:digest':
            realm = log.progress(color('Onvif REALM', YELLOW))
            realm.status('requesting')
            """ We need to get correct REALM, as it differs for newer devices  """
            rtsp = 'OPTIONS rtsp://{host}:{port}?proto=Onvif RTSP/1.1\r\nCSeq: 1\r\n\r\n'.format(
                host=self.rhost, port=self.rport)

            req = remote(self.rhost, self.rport)
            req.send(rtsp)
            rtsp = req.recv(1024)
            req.close()
            dh_realm = rtsp[rtsp.find(b'Login to'):rtsp.rfind(b'", nonce=')].decode('latin-1')
            if self.debugCalls:
                log.info('DHIP REALM: {}'.format(dh_data.get('params').get('realm')))
                log.info('RTSP REALM: {}'.format(dh_realm))
            dh_data.get('params').update({'realm': dh_realm})
            realm.success(color(dh_realm, GREEN))

        query_args = {
            "method": "global.login",
            "params": {
            },
        }
        params = pwd_manager.dhip(
            rhost=self.rhost,
            query_args=dh_data,
            username=username,
            password=password,
            login=login,
            logon=logon,
            force=self.args.force
        )
        if not params:
            login.failure(color("[dahua.py: pwd_manager.dhip] Failed", RED))
            return False

        if self.ssl:
            params.update({"Encryption": "SSL"})

        query_args.get('params').update(params)

        dh_data = self.send_call(query_args, errorcodes=True, login=True)
        if not dh_data:
            return False

        # Device not initialised
        if dh_data.get('error') and dh_data.get('error').get('code') == 268632086:
            login.failure(color('Device not initialised! ({})'.format(dh_data.get('params')), RED))
            return False

        # Device locked
        elif dh_data.get('error') and dh_data.get('error').get('code') == 268632081:
            login.failure(color('Device locked! ({})'.format(dh_data.get('params')), RED))
            return False

        elif not dh_data.get('result'):
            login.failure(color('global.login: {}'.format(dh_data.get('error')), RED))
            return False

        login.success(color('Success', GREEN))

        if self.args.save:
            pwd_manager.save_host(
                rhost=self.rhost,
                rport=self.rport,
                proto=self.proto,
                username=username,
                password=password,
                dh_realm=dh_realm,
                relay=self.args.relay,
                events=self.events,
                logon=logon
            )
            return False

        if not self.args.dump:
            if dh_data.get('params'):
                keep_alive = dh_data.get('params').get('keepAliveInterval')
            else:
                keep_alive = 30
            _thread.start_new_thread(self._p2p_keepalive, (keep_alive,))

        return True

    #
    # 3DES/DVRIP Login function
    #
    def dahua_dvrip_login(self, username=None, password=None, logon=None):
        login = log.progress(color('Login', YELLOW))
        dh_data = ''
        dh_realm = None

        pwd_manager = PwdManager()

        if self.proto == '3des':

            dh_data = pwd_manager.dvrip(
                rhost=self.rhost,
                username=username,
                password=password,
                proto=self.proto,
                login=login
            )
            if not dh_data:
                return None

            if logon == 'old_3des':
                """ all characters above 8 will be stripped """
                self.header = \
                    p32(0xa0050060, endian='big') + p32(0x0) + dh_data.get('username') + \
                    dh_data.get('password') + p64(0x040200010000a1aa, endian='big')
            else:
                """ all characters above 8 will be stripped """
                self.header = \
                    p32(0xa0000000, endian='big') + p32(0x0) + dh_data.get('username') + \
                    dh_data.get('password') + p64(0x050200010000a1aa, endian='big')

            try:
                dh_data = self.p2p(None)
            except EOFError:
                return False
            # if not dh_data:
            #     return None

        elif self.proto == 'dvrip':

            #
            # REALM & RANDOM Request
            #
            self.header = p32(0xa0010000, endian='big') + (p8(0x00) * 20) + p64(0x050201010000a1aa, endian='big')

            try:
                dh_data = self.p2p(None)
            except EOFError:
                return False

            if not dh_data or not len(dh_data):
                login.failure("Realm")
                return None

            dh_realm = dh_data[dh_data.find('Login to'):dh_data.find('\r\n')]
            dh_random = dh_data[dh_data.rfind(':') + 1:dh_data.rfind('\r\n') - 2]

            dh_data = pwd_manager.dvrip(
                rhost=self.rhost,
                username=username,
                password=password,
                proto=self.proto,
                query_args={
                    "realm": dh_realm,
                    "random": dh_random
                })

            if not dh_data:
                return None

            self.header = \
                p32(0xa0050000, endian='big') + p32(len(dh_data.get('hash'))) + \
                (p8(0x00) * 16) + p64(0x050200080000a1aa, endian='big')

            # Don't expect any data here, just check for p2p failure
            dh_data = self.p2p(dh_data.get('hash').encode('latin-1'))
            if dh_data is None:
                return None

        if self.ErrorCode[:2] == b'\x00\x08':
            login.success(color('Success', GREEN))
        elif self.ErrorCode[:2] == b'\x01\x00':
            login.failure('Authentication failed: {} tries left {}'.format(
                u16(self.AuthCode[0:2], endian='big'),
                '(BUG: SessionID = {})'.format(self.SessionID) if self.SessionID else '')
            )
            return False
        elif self.ErrorCode[:2] == b'\x01\x01':
            login.failure('Username invalid')
            return False
        elif self.ErrorCode[:2] == b'\x01\x04':
            login.failure('Account locked: {}'.format(dh_data))
            return False
        elif self.ErrorCode[:2] == b'\x01\x05':
            login.failure('Undefined code: 0x01 0x05')
            return False
        elif self.ErrorCode[:2] == b'\x01\x11':
            login.failure('Device not initialised')
            return False
        elif self.ErrorCode[:2] == b'\x01\x13':
            login.failure('Not implemented')
            return False
        elif self.ErrorCode[:2] == b'\x03\x03':
            login.failure('User already logged in')
            return False
        else:
            login.failure(color('Unknown ErrorCode: {}'.format(self.ErrorCode[:2]), RED))
            return False

        if self.args.save and not self.proto == '3des':
            pwd_manager.save_host(
                rhost=self.rhost,
                rport=self.rport,
                proto=self.proto,
                username=username,
                password=password,
                dh_realm=dh_realm,
                relay=self.args.relay,
                events=self.events,
                logon=logon
            )
            return False

        if not self.args.dump:
            """ Seems to be stable """
            keep_alive = 30
            _thread.start_new_thread(self._p2p_keepalive, (keep_alive,))

        self.header = self.proto_header()

        return True

    def proto_header(self):

        if self.proto == 'dhip':
            return p64(0x2000000044484950, endian='big') + '_SessionHexID__ID__LEN_'.encode('latin-1') + \
                   p32(0x0) + '_LEN_'.encode('latin-1') + p32(0x0)
        else:
            # DVRIP
            return p32(0xf6000000, endian='big') + '_LEN__ID_'.encode('latin-1') + p32(0x0) + \
                   '_LEN_'.encode('latin-1') + p32(0x0) + '_SessionHexID_'.encode('latin-1') + p32(0x0)

    def subscribe_notify(self, status=False):
        """Only used with http/https proto"""
        if status:
            if self.proto in ['http', 'https']:
                self.recv_stream_status.wait(0.200)
            return True

        self.remote.open_stream(self.SessionID)

        while True:
            self.recv_stream_status.clear()
            event_data = self.remote.recv_stream()
            self._debug("RECV ({})".format(len(event_data)), event_data)
            if not event_data:
                log.failure('[subscribe_notify] == 0')
                # self.event.set()
                return False
            for NUM in range(0, len(event_data)):
                self.client_notify(json.dumps(event_data[NUM]))
