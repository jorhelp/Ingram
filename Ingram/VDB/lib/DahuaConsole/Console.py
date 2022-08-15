#!/usr/bin/env python3

"""
Author: bashis <mcw noemail eu> 2019-2021
Subject: Dahua Debug Console
"""
import argparse
import _thread

from utils import *
from pwdmanager import PwdManager
from dahua import DahuaFunctions
from servers import Servers


class DebugConsole(Servers):
    """ main init and loop for console I/O """
    """ If multiple Consoles is attached to one device, all attached Consoles will receive same output from device """
    def __init__(self, dargs):
        super(DebugConsole, self).__init__()

        self.dargs = dargs

        if self.dargs.dump or self.dargs.test:
            self.dump()
            return

        if self.dargs.restore:
            self.restore(self.dargs.restore)
            return

        self.main_console()

    #
    # Main console for instances
    #
    def main_console(self):

        #
        # Additional Cmd list
        #
        cmd_list = {
            'certificate': {
                'cmd': 'self.dh.get_remote_info("certificate")',
                'help': 'Dump some information of remote certificate',
            },
            'config': {
                'cmd': 'self.dh.config_members(msg)',
                'help': 'remote config (-h for params)',
            },
            'console': {
                'cmd': 'self.dh_console(msg)',
                'help': 'console instance handling (-h for params)',
            },
            'debug': {
                'cmd': 'self.debug_instance(msg)',
                'help': 'debug instance (-h for params)',
            },
            'device': {
                'cmd': 'self.dh.get_remote_info(msg)',
                'help': 'Dump some information of remote device',
            },
            'dhp2p': {
                'cmd': 'self.dh.get_remote_info("dhp2p")',
                'help': 'Dump some information of dhp2p',
            },
            'diag': {
                'cmd': 'self.dh.interim_remote_diagnose(msg)',
                'help': 'Interim Remote Diagnose (-h for params)',
            },
            'door': {
                'cmd': 'self.dh.open_door(msg)',
                'help': 'open door (-h for params)',
            },
            'events': {
                'cmd': 'self.dh.event_manager(msg)',
                'help': 'Subscribe on events from eventManager (-h for params)',
            },
            'fuzz': {
                'cmd': 'self.dh.fuzz_service(msg)',
                'help': 'fuzz service methods (-h for params)',
            },
            'ldiscover': {
                'cmd': 'self.dh.dh_discover(msg)',
                'help': 'Device Discovery from this script (-h for params)',
            },
            'dlog': {
                'cmd': 'self.dh.dlog(msg)',
                'help': 'Log stuff (-h for params)',
            },
            'network': {
                'cmd': 'self.dh.net_app(msg)',
                'help': 'Network stuff (-h for params)',
            },
            'memory': {
                'cmd': 'self.memory_info()',
                'help': 'Used memory of this script (-h for params)',
            },
            'pcap': {
                'cmd': 'self.dh.network_sniffer_manager(msg)',
                'help': 'remote device pcap (-h for params)',
            },
            'rdiscover': {
                'cmd': 'self.dh.device_discovery(msg)',
                'help': 'Device Discovery from remote device (-h for params)',
            },
            'service': {
                'cmd': 'self.dh.list_service(msg)',
                'help': 'List remote services and "methods" (-h for params)',
            },
            'sshd': {
                'cmd': 'self.dh.telnetd_sshd(msg)',
                'help': 'Start / Stop (-h for params)',
            },
            'setDebug': {
                'cmd': 'self.dh.set_debug()',
                'help': 'Should start produce output from Console in VTO/VTH',
            },
            'telnet': {
                'cmd': 'self.dh.telnetd_sshd(msg)',
                'help': 'Start / Stop (-h for params)',
            },
            'test-config': {
                'cmd': 'self.dh.new_config(msg)',
                'help': 'New config test (-h for params)',
            },
            'ldap': {
                'cmd': 'self.dh.set_ldap()',
                'help': 'LDAP test',
            },
            'uboot': {
                'cmd': 'self.dh.u_boot(msg)',
                'help': 'U-Boot Environment Variables (-h for params)',
            },
            '"quit"': {
                'cmd': 'self.dh_console(msg)',
                'help': '"quit" active instance "quit all" to quit from all',
            },
            '"reboot"': {
                'cmd': 'self.dh_console(msg)',
                'help': '"reboot" active instance "reboot all" to reboot all',
            },
            'REBOOT': {
                'cmd': 'self.dh.reboot()',
                'help': 'Try force reboot of remote',
            },
            'dh_test': {
                'cmd': 'self.dh.dh_test(msg)',
                'help': 'TEST function (-h for params)',
            },
        }

        dh_data = None

        if not self.dargs.auth:
            dh_data = PwdManager().get_host(self.dargs.rhost)
            if not dh_data:
                log.failure(color('You need to use --auth <username>:<password>', RED))
                return False

        if self.dargs.events:
            _thread.start_new_thread(self.event_in_out_server, ())
            _thread.start_new_thread(self.terminate_daemons, ())

        try:
            #
            # Connect multiple pre-defined devices
            #
            if self.dargs.multihost and not (self.dargs.dump or self.dargs.test or self.dargs.auth or self.dargs.rhost):

                for host in range(0, len(dh_data)):
                    try:
                        self.connect_rhost(
                            rhost=dh_data[host].get('host'),
                            rport=dh_data[host].get('port'),
                            proto=dh_data[host].get('proto'),
                            username=dh_data[host].get('username'),
                            password=None,
                            events=self.dargs.events if self.dargs.events else dh_data[host].get('events'),
                            ssl=self.dargs.ssl,
                            relay_host=dh_data[host].get('relay'),
                            logon=dh_data[host].get('logon'),
                            timeout=5
                        )
                    except KeyboardInterrupt:
                        return False
                    except Exception as e:
                        print('MainConsole()', repr(e))
                        if e.args == ('Authentication failed.',):
                            return False
                        pass
                if not len(self.dhConsole):
                    return False
            #
            # Connect single device pre-defined/or w/ credentials from command line
            #
            else:
                if not self.connect_rhost(
                        rhost=self.dargs.rhost if self.dargs.auth else dh_data.get('host'),
                        rport=self.dargs.rport if self.dargs.auth else dh_data.get('port'),
                        proto=self.dargs.proto if self.dargs.auth else dh_data.get('proto'),
                        username=self.dargs.auth.split(':')[0] if self.dargs.auth else None,
                        password=self.dargs.auth.split(':')[1] if self.dargs.auth else None,
                        events=self.dargs.events if self.dargs.auth else dh_data.get('events'),
                        ssl=self.dargs.ssl,
                        relay_host=self.dargs.relay if self.dargs.auth else dh_data.get('relay'),
                        logon=self.dargs.logon if self.dargs.auth else dh_data.get('logon'),
                        timeout=5
                ):
                    return False
        except KeyboardInterrupt:
            return False
        except AttributeError as e:
            print(repr(e))
            log.failure('[MainConsole]')
            return False
        #
        # Main Console loop
        #
        while True:
            try:
                self.prompt()
                msg = sys.stdin.readline().strip()
                if not self.dh or not self.dh.remote.connected():
                    log.failure('No available instance')
                    return False
                cmd = msg.split()

                if msg:
                    if msg == 'shell' and not self.dargs.force:
                        log.failure("[shell] will execute and hang the Console/Device (DoS)")
                        log.failure("If you still want to try, run this script with --force")
                        continue
                    elif msg == 'exit' and not self.dargs.force:
                        log.failure("[exit] You really want to exit? (maybe you mean 'quit' this connection?)")
                        log.failure("If you still want to try, run this script with --force")
                        continue

                    command = None
                    for command in cmd_list:
                        if command == cmd[0]:
                            tmp = cmd_list[command]['cmd']
                            exec(tmp)
                            break
                    if command == cmd[0]:
                        continue

                    if self.dh.terminate:
                        # console kill self.dh
                        self.dh_console('console kill self.dh')
                        continue

                    if msg == 'quit' or len(cmd) == 2 and cmd[0] == 'quit' and cmd[1] == 'all':

                        if len(cmd) == 2 and cmd[1] == 'all':
                            self.quit_host(quit_all=True)
                            return True
                        if not self.quit_host(quit_all=False, msg=msg):
                            return False

                    elif msg == 'shutdown' or msg == 'reboot' or len(cmd) == 2 and cmd[1] == 'all':

                        if len(cmd) == 2 and cmd[1] == 'all':
                            self.quit_host(quit_all=True, msg=msg)
                            return True

                        if not self.quit_host(quit_all=False, msg=msg):
                            return False

                    elif msg == 'help':
                        self.dh.run_cmd(msg)
                        self.dh.subscribe_notify(status=True)
                        log.info("Local cmd:")
                        for command in cmd_list:
                            log.success("{}: {}".format(command, cmd_list[command]['help']))

                    else:
                        if not self.dh.run_cmd(msg):
                            log.failure("Invalid command: 'help' for help")
                            continue
                        self.dh.subscribe_notify(status=True)

            except KeyboardInterrupt:
                pass
            except EOFError as e:
                print('[Console]', repr(e))
                return False
#            except Exception as e:
#                print('[Console]', repr(e))
#                pass

    @staticmethod
    def memory_info():
        from resource import getrusage, RUSAGE_SELF
        memory = getrusage(RUSAGE_SELF).ru_maxrss
        if sys.platform == 'darwin':
            memory = memory / 1024
        log.info("Memory usage: {}".format(size(memory)))

    def set_config(self, key, table):
        method_name = 'configManager'
        self.dh.instance_service(method_name, start=True)
        object_id = self.dh.instance_service(method_name, pull='object')

        query_args = {
            "method": "configManager.setConfig",
            "params": {
                "table": table,
                "name": key,
            },
            "object": object_id,
        }
        log.info(f"Setting {key}")
        dh_data = self.dh.send_call(query_args)
        if not dh_data:
            return
        print(json.dumps(dh_data, indent=4))

    def restore(self, fd):
        self.connect()
        """ Restores configuration from json file"""
        config = json.loads(fd.read())
        for k, v in config['params']['table'].items():
            self.set_config(k, v)

    def connect(self):
        """ Handle the '--dump' options from command line """

        self.dhConsole = {}
        self.dhConsoleNo = 0
        self.udp_server = None

        if not self.connect_rhost(
                rhost=self.dargs.rhost,
                rport=self.dargs.rport,
                proto=self.dargs.proto,
                username=self.dargs.auth.split(':')[0] if self.dargs.auth else None,
                password=self.dargs.auth.split(':')[1] if self.dargs.auth else None,
                events=self.dargs.events,
                ssl=self.dargs.ssl,
                relay_host=self.dargs.relay,
                logon=self.dargs.logon,
                timeout=5
        ):
            return None

        if self.dargs.test:
            self.dh.dh_test('test')
            return None

    def dump(self):
        self.connect()
        if self.dargs.dump == 'config':
            self.dh.config_members("{} {}".format("config", self.dargs.dump_argv if self.dargs.dump_argv else "all"))
            self.dh.logout()
            return None
        elif self.dargs.dump == 'service':
            self.dh.listService("{} {}".format("service", self.dargs.dump_argv if self.dargs.dump_argv else "all"))
            self.dh.logout()
            return None
        elif self.dargs.dump == 'device':
            self.dh.getRemoteInfo('device')
            self.dh.logout()
            return None
        elif self.dargs.dump == 'discover':
            self.dh.deviceDiscovery("{} {}".format("discover", self.dargs.dump_argv))
            self.dh.logout()
            return None
        elif self.dargs.dump == 'test':
            self.dh.dh_test('test')
            self.dh.logout()
            return None
        elif self.dargs.dump == 'dlog':
            self.dh.dlog('test')
            self.dh.logout()
            return None
        else:
            log.error('No such dump: {}'.format(self.dargs.dump))
            return None

    def quit_host(self, quit_all=False, msg=None):
        """ Quit from single device, or 'all' """

        cmd = ''
        session = None
        if msg:
            cmd = msg.split()

        if quit_all:
            while True:
                for session in self.dhConsole:
                    log.warning("{}: {} ({})".format(
                        session,
                        self.dhConsole.get(session).get('device'),
                        self.dhConsole.get(session).get('host'),
                    ))
                    self.dh = self.dhConsole.get(session).get('instance')
                    if msg and len(cmd) == 2 and cmd[1] == 'all':
                        self.dh.cleanup()
                        self.dh.run_cmd(cmd[0])
                        if not self.dh.console_attach and cmd[0] == 'reboot':
                            self.dh.reboot(delay=2)
                    self.dh.logout()
                    self.dh.terminate = True
                    break
                del self.dh
                self.dhConsole.pop(session)
                if not len(self.dhConsole):
                    break
            if self.tcp_server:
                self.tcp_server.close()
            if self.udp_server:
                self.udp_server.close()
            return True
        else:
            for session in self.dhConsole:
                if self.dhConsole.get(session).get('instance') == self.dh:
                    log.warning("{}: {} ({})".format(
                        session,
                        self.dhConsole.get(session).get('device'),
                        self.dhConsole.get(session).get('host'),
                    ))
                    self.dh.cleanup()
                    self.dh.run_cmd(msg)
                    if not self.dh.console_attach and msg == 'reboot':
                        self.dh.reboot(delay=2)
                    self.dh.logout()
                    self.dh.terminate = True
                    self.dhConsole.pop(session)
                    del self.dh
                    break

            if not self.dh_instance():
                return False
            return True

    def dh_instance(self, show=False):
        """Show connected instance"""

        if not show:
            if not len(self.dhConsole):
                self.dh = False
                return False

            for session in self.dhConsole:
                self.dh = self.dhConsole.get(session).get('instance')
                break

        for session in self.dhConsole:
            log.info('Console: {}, Device: {} ({}) {} {}'.format(
                session,
                self.dhConsole.get(session).get('device'),
                self.dhConsole.get(session).get('host'),
                color('Active', GREEN) if self.dhConsole.get(session).get('instance') == self.dh else '',
                '{} {}'.format(
                    color(
                        '(calls)'.format(self.dhConsole.get(session).get('instance').debug), YELLOW)
                    if self.dhConsole.get(session).get('instance').debugCalls else '',

                    color(
                        '(traffic: {})'.format(self.dhConsole.get(session).get('instance').debug), YELLOW)
                    if self.dhConsole.get(session).get('instance').debug else '',
                )))
        return True

    @staticmethod
    def prompt():
        prompt_text = "\033[92m[\033[91mConsole\033[92m]\033[0m# "
        sys.stdout.write(prompt_text)
        sys.stdout.flush()

    def dh_console(self, msg):
        """Handling connection/kill of instance from main Console"""

        cmd = msg.split()

        usage = {
            "conn": {
                "all": "(connect all pre-defined devices)",
                "<username>": "<password> <host> [[<port>] | [ <dvrip | dhip | 3des> [<port>]]",
                "<host>": "(connect pre-defined device <host>)"
            },
            "kill": {
                "dh<#>": "(kill instance dh<#>)"
            },
            "dh<#>": "(switch active console. e.g. 'console dh0')"
        }

        if len(cmd) == 2 and cmd[1] == '-h':

            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        elif len(cmd) == 3 and cmd[1] == 'kill':

            if len(cmd) == 2:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True
            try:
                tmp = self.dhConsole.get(cmd[2]).get('instance')
            except AttributeError:
                log.failure('Console ({}) do not exist'.format(cmd[2]))
                return False

            self.dhConsole.pop(cmd[2])

            tmp.terminate = True
            tmp.logout()

            del tmp

            if not self.dh_instance():
                return False
            return True

        elif len(cmd) >= 2 and cmd[1] == 'conn':

            if len(cmd) > 2 and cmd[2] == '-h':
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False

            if len(cmd) == 2 or len(cmd) == 3:

                dh_data = PwdManager().get_host()

                if len(cmd) == 2:
                    """ console conn """

                    for host in range(0, len(dh_data)):

                        conn = next(
                            (
                                session for session in self.dhConsole
                                if dh_data[host].get('host') == self.dhConsole.get(session).get('host')
                            ), None)
                        log.info('{} {}'.format(
                            dh_data[host].get('host'), 'Connected ({})'.format(color(conn, GREEN)) if conn else ''))

                    return True

                if cmd[2] == 'all':
                    """ console conn all """
                    for host in range(0, len(dh_data)):
                        if not self.connect_rhost(
                                rhost=dh_data[host].get('host'),
                                rport=dh_data[host].get('port'),
                                proto=dh_data[host].get('proto'),
                                username=dh_data[host].get('username'),
                                password=None,
                                events=self.dargs.events if self.dargs.events else dh_data[host].get('events'),
                                relay_host=dh_data[host].get('relay'),
                                ssl=self.dargs.ssl,
                                timeout=5):
                            pass
                    return True

                """ console conn <host> """
                host = check_host(cmd[2])

                if not host:
                    log.failure('"{}" not valid host'.format(cmd[2]))
                    return False

                dh_data = PwdManager().get_host(host=host)
                if not dh_data:
                    return False

                if not self.connect_rhost(
                        rhost=dh_data.get('host'),
                        rport=dh_data.get('port'),
                        proto=dh_data.get('proto'),
                        username=dh_data.get('username'),
                        password=None,
                        events=self.dargs.events if self.dargs.events else dh_data.get('events'),
                        ssl=self.dargs.ssl,
                        relay_host=dh_data.get('relay'),
                        timeout=5):
                    return False

                if not self.dh_instance(show=True):
                    return False
                return True

            elif len(cmd) == 4:
                log.failure('Need at least "rhost"')
                return False
            elif len(cmd) >= 5 and not len(cmd) > 5:
                rhost = cmd[4]
                rport = cmd[5] if len(cmd) == 6 else 37777
                proto = 'dvrip'
            elif len(cmd) >= 6 and cmd[5] == 'dhip':
                rhost = cmd[4]
                proto = cmd[5]
                rport = cmd[6] if len(cmd) == 7 else 5000
            elif len(cmd) >= 6 and cmd[5] == 'dvrip' or cmd[5] == '3des':
                rhost = cmd[4]
                proto = cmd[5]
                rport = cmd[6] if len(cmd) == 7 else 37777
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False

            log.info('Connecting with "{}" to {}:{}'.format(proto, rhost, rport))
            if not self.connect_rhost(
                    # rhost=cmd[4],
                    rhost=rhost,
                    rport=rport,
                    proto=proto,
                    username=cmd[2],
                    password=cmd[3],
                    events=self.dargs.events,
                    ssl=self.dargs.ssl,
                    # TODO: add relay_host
                    # relay_host=,
                    timeout=5):
                return False

        elif len(cmd) == 2:

            if cmd[1] == '-h':
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False

            try:
                self.dh = self.dhConsole.get(cmd[1]).get('instance')
            except AttributeError:
                log.failure("Console [{}] do not exist".format(cmd[1]))
                return

        if not self.dh_instance(show=True):
            return False
        return True

    def debug_instance(self, msg):
        """ Handle 'debug' command from main Console """

        cmd = msg.split()

        usage = {
            "object": "(dict with info about attached services)",
            "instance": "(dict with connection details of instance)",
            "calls": "<0|1> (debug internal calls)",
            "traffic": "(debug DHIP/DVRIP traffic)",
            "test": "test"
        }
        if not len(cmd) > 1:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return

        if cmd[1] == 'object':
            self.dh.instance_service(method_name="", list_all=True)

        elif cmd[1] == 'test':
            object_methods = [
                method_name for method_name in dir(self.dh)
                if callable(getattr(self.dh, method_name))]
            print(object_methods)

        elif cmd[1] == 'instance':
            for dh in self.dhConsole:
                dh_data = '{}'.format(help_msg(dh))
                for key in self.dhConsole.get(dh):
                    dh_data += '[{}] = {}\n'.format(key, self.dhConsole.get(dh).get(key))
                log.info(dh_data)
            return True

        elif cmd[1] == 'calls':

            usage = {
                "calls": {
                    "0": "(debug off)",
                    "1": "(debug on)",
                }
            }

            if len(cmd) == 2 or len(cmd) == 3 and cmd[2] == '-h':
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            else:
                try:
                    if int(cmd[2]) < 0 or int(cmd[2]) > 1:
                        log.info('{}'.format(help_all(msg=msg, usage=usage)))
                        return False
                    self.dh.debugCalls = int(cmd[2])

                    log.info('{} {}: {}'.format(cmd[0], cmd[1], self.dh.debugCalls))

                except ValueError:
                    log.failure("Not valid debug code: {}".format(cmd[2]))
                    return False
                return True

        elif cmd[1] == 'traffic':
            usage = {
                "traffic": {
                    "0": "(debug off)",
                    "1": "(JSON traffic)",
                    "2": "(hexdump traffic)",
                    "3": "(hexdump + JSON traffic)",
                }
            }

            if len(cmd) == 2 or len(cmd) == 3 and cmd[2] == '-h':
                if len(cmd) <= 3:
                    log.info('{}'.format(help_all(msg=msg, usage=usage)))
                    return True
            else:
                try:
                    if int(cmd[2]) < 0 or int(cmd[2]) > 3:
                        log.info('{}'.format(help_all(msg=msg, usage=usage)))
                        return False
                    self.dh.debug = int(cmd[2])

                    log.info('{} {}: {}'.format(cmd[0], cmd[1], self.dh.debug))
                except ValueError:
                    log.failure("Not valid debug code: {}".format(cmd[2]))
                    return False
                return True

        else:
            log.failure('No such command ({})'.format(msg))
            return True


def main():
    banner = '[Dahua Debug Console 2019-2021 bashis <mcw noemail eu>]\n'

    proto_choices = [
        'dhip',
        'dvrip',
        '3des',
        'http',
        'https'
    ]
    logon_choices = [
        'wsse',
        'loopback',
        'netkeyboard',
        'onvif:plain',
        'onvif:digest',
        'onvif:onvif',
        'plain',
        'ushield',
        'ldap',
        'ad',
        'cms',
        'local',
        'rtsp',
        'basic',
        'old_digest',
        'old_3des',
        'gui'
    ]
    dump_choices = [
        'config',
        'service',
        'device',
        'discover',
        'log',
        'test'
    ]

    discover_choices = [
        'dhip',
        'dvrip'
    ]

    parser = argparse.ArgumentParser(description=('[*] ' + banner + ' [*]'))
    parser.add_argument('--rhost', required=False, type=str, default=None, help='Remote Target Address (IP/FQDN)')
    parser.add_argument('--rport', required=False, type=int, help='Remote Target Port')
    parser.add_argument(
        '--proto', required=False, type=str, choices=proto_choices, default='dvrip', help='Protocol [Default: dvrip]'
    )
    parser.add_argument(
        '--relay', required=False, type=str, default=None, help='ssh://<username>:<password>@<host>:<port>'
    )
    parser.add_argument(
        '--auth', required=False, type=str, default=None, help='Credentials (username:password) [Default: None]')
    parser.add_argument(
        '--ssl', required=False, default=False, action='store_true', help='Use SSL for remote connection')
    parser.add_argument(
        '-d', '--debug', required=False, default=0, const=0x1, dest="debug", action='store_const', help='JSON traffic'
    )
    parser.add_argument(
        '-dd', '--ddebug', required=False, default=0, const=0x2, dest="ddebug", action='store_const',
        help='hexdump traffic'
    )
    parser.add_argument(
        '--dump', required=False, default=False, type=str, choices=dump_choices, help='Dump remote config')
    parser.add_argument(
        '--restore', required=False, default=False, type=argparse.FileType('r'),
        help='Restores device config from json config')
    parser.add_argument('--dump_argv', required=False, default=None, type=str, help='ARGV to --dump')
    parser.add_argument('--test', required=False, default=False, action='store_true', help='test w/o login attempt')
    parser.add_argument(
        '--multihost', required=False, default=False, action='store_true', help='Connect hosts from "dhConsole.json"'
    )
    parser.add_argument(
        '--save', required=False, default=False, action='store_true', help='Save host hash to "dhConsole.json"'
    )
    parser.add_argument(
        '--events', required=False, default=False, action='store_true', help='Subscribe to events [Default: False]'
    )
    parser.add_argument('--discover', required=False, type=str, choices=discover_choices, help='Discover local devices')
    parser.add_argument(
        '--logon', required=False, type=str, choices=logon_choices, default='default', help='Logon types')
    parser.add_argument(
        '-f', '--force', required=False, default=False, action='store_true', help='Bypass stops for dangerous commands'
    )
    parser.add_argument('--calls', required=False, default=False, action='store_true', help='Debug internal calls')
    dargs = parser.parse_args()

    """ We want at least one argument, so print out help """
    if len(sys.argv) == 1:
        parser.parse_args(['-h'])

    log.info(banner)

    dargs.debug = dargs.debug + dargs.ddebug
    """
    if not dargs.relay:
        if dargs.proto == 'http' or dargs.proto == 'https':
            log.failure('proto "{}" works only with relay'.format(dargs.proto))
            return False
    """
    if dargs.logon in logon_choices:
        if dargs.proto not in ['dhip', 'http', 'https', '3des']:
            dargs.proto = 'dhip'
        if dargs.logon in ['loopback', 'netkeyboard']:
            if not dargs.auth:
                dargs.auth = 'admin:admin'

    if (dargs.proto == 'dvrip' or dargs.proto == '3des') and not dargs.rport:
        dargs.rport = 37777
    elif dargs.proto == 'dhip' and not dargs.rport:
        dargs.rport = 5000
    elif dargs.proto == 'http' and not dargs.rport:
        dargs.rport = 80
    elif dargs.proto == 'https' and not dargs.rport:
        dargs.rport = 443

    if dargs.ssl and not dargs.relay:
        if not dargs.force:
            log.failure("SSL do not fully work")
            log.failure("If you still want to try, run this script with --force")
            return False
        dargs.ssl = True
        if not dargs.rport:
            dargs.rport = '443'

    """ Check if RPORT is valid """
    if not check_port(dargs.rport):
        log.failure("Invalid RPORT - Choose between 1 and 65535")
        return False

    """ Check if RHOST is valid IP or FQDN, get IP back """
    if dargs.rhost is not None:
        if not check_host(dargs.rhost):
            log.failure("Invalid RHOST")
            return False

    if not dargs.discover:
        if dargs.rhost is None and not dargs.multihost:
            log.failure("[required] --multihost or --rhost")
            return False

    if dargs.ssl:
        log.info("SSL Mode Selected")

    if dargs.discover:
        if not dargs.rhost:
            if dargs.discover == 'dhip':
                """ Multicast """
                dargs.rhost = '239.255.255.251'
            elif dargs.discover == 'dvrip':
                """ Broadcast """
                dargs.rhost = '255.255.255.255'
        dh = DahuaFunctions(rhost=dargs.rhost, relay_host=dargs.relay, dargs=dargs)
        dh.dh_discover("ldiscover {} {}".format(dargs.discover, dargs.rhost))
    else:
        DebugConsole(dargs=dargs)

    log.info("All done")


if __name__ == '__main__':
    main()
