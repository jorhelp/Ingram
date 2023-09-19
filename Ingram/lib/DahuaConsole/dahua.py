import copy

from Crypto.PublicKey import RSA
from OpenSSL import crypto
from pathlib import Path

""" Local imports """
from utils import *
from net import Network


class DahuaFunctions(Network):
    """ Dahua instance """
    def __init__(
            self, rhost=None, rport=None, proto=None, events=False, ssl=False,
            relay_host=None, timeout=5, udp_server=True, dargs=None
    ):
        super(DahuaFunctions, self).__init__()

        self.rhost = rhost
        self.rport = rport
        self.proto = proto
        self.events = events
        self.ssl = ssl
        self.relay_host = relay_host
        self.timeout = timeout
        self.udp_server = udp_server
        self.args = dargs

        self.debug = dargs.debug
        self.debugCalls = dargs.calls				# Some internal debugging

        self.fuzzServiceDB = {}				# Used when fuzzing services

        self.DeviceType = '(null)'

        self.networkSnifferPath = None
        self.networkSnifferID = None
        self.dh_sniffer_nic = None

        self.attach_only = []
        self.Attach = []
        self.fuzz_factory = []

    #
    # Send command to remote console, if not attached just ignore sending
    #
    def run_cmd(self, msg):

        query_args = {
            "SID": self.instance_service('console', pull='sid'),
            "method": "console.runCmd",
            "params": {
                "command": msg,
            },
            "object": self.instance_service('console', pull='object'),
        }
        if self.console_attach or self.args.force:
            dh_data = self.p2p(query_args)
            if dh_data is not None:
                try:
                    dh_data = json.loads(dh_data)
                except (json.decoder.JSONDecodeError, AttributeError) as e:
                    log.failure('[runCmd]: {}'.format(repr(e)))
                    print(dh_data)
                    return False

                if not dh_data.get('result'):
                    return False
                return True

    #
    # List and caches service(s)
    #
    def list_service(self, msg, fuzz=False):

        cmd = msg.split()
        service = None

        usage = {
            "": "(dump all remote services)",
            "<service>": "(dump methods for <service>)",
            "all": "(dump all remote services methods)",
            "help": "[<service>|all] (\"system\" looks like only have builtin help)",
            "[<service>|<all>]": "[save <filename>] (Save JSON to <filename>)",
        }
        if not len(cmd) == 1:
            if cmd[1] == '-h':
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

        if len(cmd) == 3 and cmd[1] == 'help':
            self.help_service(cmd[2])
            return

        if not self.RemoteServicesCache:
            self.check_for_service('dump')
            if not self.RemoteServicesCache:
                log.failure('[listService] EZIP perhaps?')
                return False

        if self.RemoteServicesCache.get('result'):
            if not self.args.dump:
                service = log.progress('Services')
                service.status("Start")
            tmp = {}
            cache = {}

            for count in range(0, len(self.RemoteServicesCache.get('params').get('service'))):
                if len(cmd) == 1:
                    print(self.RemoteServicesCache.get('params').get('service')[count])
                elif len(cmd) == 2 or len(cmd) == 4:

                    query_tmp = {
                        "method": "",
                        "params": None,
                    }
                    query_tmp.update(
                        {'method': cmd[1] + '.listMethod' if not cmd[1] == 'all' else
                            self.RemoteServicesCache.get('params').get('service')[count] + '.listMethod'}
                    )

                    if not self.RemoteMethodsCache.get(
                            cmd[1] if not cmd[1] == 'all'
                            else self.RemoteServicesCache.get('params').get('service')[count]):
                        """ 'system.listMethod' not working with multicall """
                        if query_tmp.get('method') == 'system.listMethod':
                            dh_data = self.send_call(query_tmp)
                            tmp.update({query_tmp.get('method').split('.')[0]: dh_data})

                            dh_data.pop('result')
                            dh_data.pop('id')
                            """SessionID bug: 'method': 'snapManager.listMethod'"""
                            dh_data.pop('session') if dh_data.get('session') else log.failure(
                                "[listService] SessionID BUG ({})".format(query_tmp.get('method').split('.')[0]))
                            self.RemoteMethodsCache.update({query_tmp.get('method').split('.')[0]: dh_data})

                            if not cmd[1] == 'all':
                                break
                            continue
                        else:
                            self.send_call(query_tmp, multicall=True)
                    else:
                        tmp.update({
                            cmd[1] if not cmd[1] == 'all'
                            else self.RemoteServicesCache.get('params').get('service')[count]:
                                self.RemoteMethodsCache.get(
                                    cmd[1] if not cmd[1] == 'all'
                                    else self.RemoteServicesCache.get('params').get('service')[count])
                        })

                    if not self.args.dump:
                        service.status('{} of {}'.format(
                            count+1, len(self.RemoteServicesCache.get('params').get('service'))))

                    if not cmd[1] == 'all':
                        break

            dh_data = self.send_call(None, multicall=True, multicallsend=True)
            # print('[list_service]', dh_data)

            if dh_data is None:
                cache = tmp
            elif dh_data is not None:
                for method_name in copy.deepcopy(dh_data):
                    service.status(method_name)

                    if not dh_data.get(method_name).get('result'):
                        log.failure("[listService] Failure to fetch: {}".format(method_name.split('.')[0]))
                        continue
                    dh_data.get(method_name).pop('result')
                    dh_data.get(method_name).pop('id')
                    """SessionID bug: 'method': 'snapManager.listMethod'"""
                    if dh_data.get(method_name).get('session'):
                        dh_data.get(method_name).pop('session')
                    """if dh_data.get(method_name).get('session') else log.failure(
                        "[listService] SessionID BUG ({})".format(method_name.split('.')[0]))"""

                    cache.update({method_name.split('.')[0]: dh_data.get(method_name)})
                    self.RemoteMethodsCache.update(cache)
                if len(tmp):
                    cache.update(tmp)

            if not self.args.dump:
                service.success('Done')
            if fuzz:
                return self.RemoteMethodsCache
            if len(cmd) == 4 and cmd[2] == 'save':
                if len(cache):
                    return self.save_to_file(file_name=cmd[3], dh_data=cache)
                log.failure('[listService] (save) Empty')
            if not len(cmd) == 1:
                if len(cache):
                    print(json.dumps(cache, indent=4))
                else:
                    log.failure('[listService] (cache) Empty')

            return True
        else:
            log.failure("[listService] {}".format(self.RemoteServicesCache))
            return False

    #
    # Used by 'list_service()' and 'config_members()' to save result to file
    #
    def save_to_file(self, file_name, dh_data):

        if not self.args.force:
            path = Path(file_name)
            if path.exists():
                log.failure("[saveToFile] File {} exist (force with -f at startup)".format(file_name))
                return False
        try:
            with open(file_name, 'w') as fd:
                fd.write(json.dumps(dh_data))
            log.success("[saveToFile] Saved to: {}".format(file_name))
        except IOError as e:
            log.failure("[saveToFile] Save {} fail: {}".format(file_name, e))
            return False
        return True

    def help_service(self, msg):
        """ In principal useless function, as the only API help seems to cover 'system' only """
        cmd = msg.split()

        dh_services = self.list_service(msg='service ' + cmd[0], fuzz=True)

        for key in dh_services.keys():
            for method in dh_services.get(key).get('params').get('method'):

                query_args = {
                    "method": "system.methodHelp",
                    "params": {
                        "method_name": method,
                    },
                }
                dh_data = self.send_call(query_args)
                query_args = {
                    "method": "system.methodSignature",
                    "params": {
                        "method_name": method,
                    },
                }
                dh_data2 = self.send_call(query_args)

                if not dh_data and not dh_data2:
                    continue

                log.info("Method: {:30}Params: {:20}Description: {}".format(
                    method,
                    dh_data2.get('params').get('signature', '(null)'),
                    dh_data.get('params').get('description', '(null)')
                ))

    def reboot(self, delay=1):
        """ 'Hard reboot' of remote device """
        query_args = {
            "method": "magicBox.reboot",
            "params": {
                "delay": delay
            },
        }

        dh_data = self.send_call(query_args)
        if dh_data.get('result'):
            log.success("Trying to force reboot")
        else:
            log.warning("Trying to force reboot")
        self.socket_event.set()
        self.logout()

    def logout(self):
        """ Try graceful logout """

        if not self.remote.connected():
            log.failure('[logout] Not connected, cannot exit clean')
            return False
        """ Will exit the instance by check daemon thread """
        if self.terminate and self.remote.connected():
            self.remote.close()
            if self.relay:
                self.relay.close()
            return False

        """keepAlive failed or terminate
        Clean up before we quit, if needed (and can do so)
        """
        if not self.event.is_set():
            self.cleanup()

        """ Stop console (and possible others) """
        self.instance_service(clean=True)

        query_args = {
            "method": "global.logout",
            "params": None,
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            log.failure("[logout] global.logout: {}".format(dh_data))
            self.remote.close()
            if self.relay:
                self.relay.close()
            return False
        if dh_data.get('result'):
            log.success("Logout")
            self.remote.close()
            if self.relay:
                self.relay.close()
        return True

    def config_members(self, msg):

        cmd = msg.split()

        usage = {
            "members": "(show config members)",
            "all": "(dump all remote config)",
            "<member>": "(dump config for <member>)",
            "[<member>|<all>]": "[save <filename>] (Save JSON to <filename>)",
            "": "(Use 'ceconfig' in Console to set/get)",
        }
        if len(cmd) == 1 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return False

        if cmd[1] == 'members':
            query_args = {
                "method": "configManager.getMemberNames",
                "params": {
                    "name": "",
                },
            }
        else:
            if cmd[1] == 'all':
                cmd[1] = 'All'
            query_args = {
                "method": "configManager.getConfig",
                "params": {
                    "name": cmd[1],
                },
            }
        dh_data = self.send_call(query_args, errorcodes=True)
        if not dh_data or not dh_data.get('result'):
            log.failure('[config_members] Error: {}'.format(dh_data.get('error') if dh_data else False))
            return False

        dh_data.pop('id')
        dh_data.pop('session')
        dh_data.pop('result')

        if len(cmd) == 4 and cmd[2] == 'save':
            return self.save_to_file(file_name=cmd[3], dh_data=dh_data)

        print(json.dumps(dh_data, indent=4))

        return

    def open_door(self, msg):
        """ VTO specific functions (not complete) """

        cmd = msg.split()

        usage = {
            "<n>": {
                "open": "(open door <n>)",
                "close": "(close door <n>)",
                "status": "(status door <n>)",
                "finger": "(<Undefined>)",
                "password": "(<Undefined>)",
                "lift": "(<Undefined> Not working)",
                "face": "(<Undefined> Not working)",
            }
        }
        if len(cmd) != 3 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        method_name = 'accessControl'

        try:
            door = int(cmd[1])
        except ValueError:
            log.failure("[open_door] Invalid door number {}".format(cmd[1]))
            self.instance_service(method_name, stop=True)
            return False

        self.instance_service(method_name, params={"channel": door}, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        if cmd[2] == 'open':
            query_args = {
                "method": "accessControl.openDoor",
                "params": {
                    "DoorIndex": door,
                    "ShortNumber": "9901#0",
                    "Type": "Remote",
                    "OpenDoorType": "Remote",
                    # "OpenDoorType": "Dahua",
                    # "OpenDoorType": "Local",
                    "UserID": "",
                },
                "object": object_id,
            }

            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)
            if not dh_data:
                return

            log.info("door: {} {}".format(door, "Success" if dh_data.get('result') else "Failure"))

        elif cmd[2] == 'close':
            query_args = {
                "method": "accessControl.closeDoor",  # {"id":21,"result":true,"session":2147483452}
                "params": {
                    # "Type": "Remote",
                    # "UserID":"",
                },
                "object": object_id,
            }

            # print(query_args)
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

        elif cmd[2] == 'status':  # Seems always to return "Status Close"
            """{"id":8,"params":{"Info":{"status":"Close"}},"result":true,"session":2147483499}"""
            query_args = {
                "method": "accessControl.getDoorStatus",
                "params": {
                    "DoorState": door,
                    # "ShortNumber": "9901#0",
                    # "Type": "Remote",
                },
                "object": object_id,
            }
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

        elif cmd[2] == 'finger':
            query_args = {
                "method": "accessControl.captureFingerprint",  # working
                "params": {
                },
                "object": object_id,
            }
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

        elif cmd[2] == 'lift':
            query_args = {
                "method": "accessControl.callLift",  # Not working
                "params": {
                    "Src": 1,
                    "DestFloor": 3,
                    "CallLiftCmd": "",
                    "CallLiftAction": "",
                },
                "object": object_id,
            }
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

        elif cmd[2] == 'password':
            query_args = {
                "method": "accessControl.modifyPassword",  # working
                "params": {
                    "type": "",
                    "user": "",
                    "oldPassword": "",
                    "newPassword": "",
                },
                "object": object_id,
            }
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

        elif cmd[2] == 'face':
            query_args = {
                "method": "accessControl.openDoorFace",  # Not working
                "params": {
                    "Status": "",
                    "MatchInfo": "",
                    "ImageInfo": "",
                },
                "object": object_id,
            }
            dh_data = self.send_call(query_args)
            print(query_args)
            print(dh_data)

            self.instance_service(method_name, stop=True)

        return

    def telnetd_sshd(self, msg):

        cmd = msg.split()
        service = None

        if cmd[0] == 'telnet':
            service = 'Telnet'
        elif cmd[0] == 'sshd':
            service = 'SSHD'

        usage = {
            "1": "(enable)",
            "0": "(disable)",
        }
        if len(cmd) == 1 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))

            return True

        if cmd[1] == '1':
            enable = True
        elif cmd[1] == '0':
            enable = False
        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return False

        query_args = {
            "method": "configManager.getConfig",
            "params": {
                "name": service,
            },
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            return

        if dh_data.get('result'):
            if dh_data['params']['table']['Enable'] == enable:
                log.failure("{} already: {}".format(cmd[0], "Enabled" if enable else "Disabled"))
                return
        else:
            log.failure("Failure: {}".format(dh_data))
            return

        dh_data['method'] = "configManager.setConfig"
        dh_data['params']['table']['Enable'] = enable
        dh_data['params']['name'] = service
        dh_data['id'] = self.ID
        dh_data.pop('result')

        dh_data = self.send_call(dh_data, errorcodes=True)

        if dh_data.get('result'):
            log.success("{}: {}".format(cmd[0], "Enabled" if enable else "Disabled"))
        else:
            log.failure("Failure: {}".format(dh_data))
            return

    @staticmethod
    def method_banned(msg):

        banned = [
            "system.listService",
            "magicBox.exit",
            "magicBox.restart",
            "magicBox.shutdown",
            "magicBox.reboot",
            "magicBox.resetSystem",
            "magicBox.config"
            "global.login",
            "global.logout",
            "global.keepAlive",
            "global.setCurrentTime",
            "DockUser.addUser",
            "DockUser.modifyPassword",
            "configManager.detach",
            "configManager.exportPackConfig",  # Exporting config in encrypted TGZ
            "configManager.secGetDefault",
            "userManager.deleteGroup",
            "userManager.setDefault",  # will erase all users
            "PhotoStation.savePhotoDesign",
            "configManager.getMemberNames",
            "PerformanceMonitoring.factory.instance",  # generates client.notifyPerformanceInfo() callback
            "PerformanceMonitoring.attach"  # generates client.notifyPerformanceInfo() callback
        ]

        try:
            banned.index(msg)
            dh_data = help_msg('Banned Match')
            dh_data += '{}\n'.format(msg)
            log.info(dh_data)
            # print('Banned Match: {}'.format(msg))
            return True
        except ValueError as e:
            print(repr(e))
            return False

    def fuzz_service(self, msg):
        """ Under development """

        cmd = msg.split()
        params = None

        usage = {
            "check": {
                "<service>": "(method for <service>)",
                "all": "(all remote services methods)",
            },
            "factory": "(fuzz factory)"
        }
        if not len(cmd) >= 2 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))

            return True

        fuzz_result = {}
        """
        Code = [
            268894211,  # Request invalid param!
            268959743,  # Unknown error! error code was not set in service!
            268632080,  # pthread error
            285278247,  # ? - with magicBox.resetSystem
            268894208,  # Request parse error!
            268894212,  # Server internal error!
            268894209,  # get component pointer failed or invalid request! (.object needed!)
            ]
        """
        #
        # TODO: Can be more than one in one call
        #
        dparams = [
            "",
            "channel",		# 0 should always be availible
            "pointer",
            "name",
            "codes",
            "service",
            "group",
            "stream",
            "uuid",
            "UUID",
            "object",
            "interval",  # PerformanceMonitoring.attach
            "composite",
            "path",
            "DeviceID",
            "points",
            "Channel",
        ]

        attach_options = [
            # {"type":"FormatPatition"},
            "Network",  # configMember
            ["All"],  # eventManager
            0,  # for channel.. etc
            1,
            # "DeviceID1",
            "none",
            # "xxxxxx",
            "System_CONFIG_NETCAMERA_INFO_0",  # uuid
            "System_CONFIG_NETCAMERA_INFO_",  # uuid
            ["System_CONFIG_NETCAMERA_INFO_0"],  # uuid
            ["System_CONFIG_NETCAMERA_INFO_"],  # uuid
            "/mnt/sd",
            "/dev/mmc0",
            "/",

            # ["Record FTP"],
            # ["Image FTP"],
            # ["FTP1"],
            # ["ISCSI1"],
            # ["NFS1"],
            # ["SMB1"],
            # ["SFTP1"],
            # ["SFTP"],
            # ["StorageGroup"],
            # ["NAS"],
            # ["Remote"],
            # ["ReadWrite"],
        ]

        try:  # [Main TRY]

            if len(cmd) == 3 and cmd[1] == 'check':

                check = log.progress('Check')
                check.status('Start')

                dh_services = self.list_service(msg='service ' + cmd[2], fuzz=True)

                for key in dh_services.keys():
                    check.status(key)

                    method_name = dh_services.get(key).get('params').get('method')
                    self.fuzzServiceDB.update({key: {
                    }})

                    try:
                        method_name.index(key + '.factory.instance')
                        self.fuzzServiceDB.get(key).update({"factory": True})

                        method_name.index(key + '.attach')
                        self.fuzzServiceDB.get(key).update({"attach": True})

                    except ValueError as e:

                        _error = str(e).split("'")[1]
                        try:
                            if _error == key + '.factory.instance':
                                self.fuzzServiceDB.get(key).update({"factory": False})
                            elif _error == key + '.attach':
                                self.fuzzServiceDB.get(key).update({"attach": False})

                            method_name.index(key + '.attach')
                            self.fuzzServiceDB.get(key).update({"attach": True})

                        except ValueError:
                            self.fuzzServiceDB.get(key).update({"attach": False})
                            pass

                self.fuzz_factory = []
                self.Attach = []
                self.attach_only = []

                for key in dh_services.keys():
                    if not self.fuzzServiceDB.get(key).get('factory') and not self.fuzzServiceDB.get(key).get('attach'):
                        if self.fuzzServiceDB.get(key):
                            self.fuzzServiceDB.pop(key)
                        continue
                    elif self.method_banned(key + '.factory.instance'):
                        if self.fuzzServiceDB.get(key):
                            self.fuzzServiceDB.pop(key)
                        continue
                    elif self.method_banned(key + '.attach'):
                        if self.fuzzServiceDB.get(key):
                            self.fuzzServiceDB.pop(key)
                        continue

                    if self.fuzzServiceDB.get(key).get('factory'):
                        self.fuzz_factory.append(key)
                    if self.fuzzServiceDB.get(key).get('factory') and self.fuzzServiceDB.get(key).get('attach'):
                        self.Attach.append(key)
                    if not self.fuzzServiceDB.get(key).get('factory') and self.fuzzServiceDB.get(key).get('attach'):
                        self.attach_only.append(key)

                check.success(
                    'Factory: {}, Attach: {}, attach_only: {}\n'.format(
                        len(self.fuzz_factory), len(self.Attach), len(self.attach_only)))

                dh_data = '{}'.format(help_msg('Summary'))
                dh_data += '{}{}\n'.format(help_msg('Factory'), ', '.join(self.fuzz_factory))
                dh_data += '{}{}\n'.format(help_msg('Attach'), ', '.join(self.Attach))
                dh_data += '{}{}\n'.format(help_msg('attach_only'), ', '.join(self.attach_only))
                log.success(dh_data)
                return

            elif len(cmd) >= 2 and cmd[1] == 'factory':

                try:
                    if not len(self.fuzz_factory):
                        log.failure('Factory is Empty')
                        return False
                except AttributeError:
                    log.failure('Firstly run {} check'.format(cmd[0]))
                    return False

                fuzz_factory = []
                if len(cmd) == 2:
                    fuzz_factory = self.fuzz_factory
                elif len(cmd) == 3:
                    if cmd[2] in self.fuzz_factory:
                        fuzz_factory.append(cmd[2])
                    else:
                        log.failure('"{}" do not exist in factory'.format(cmd[2]))
                        return False

                for method_name in fuzz_factory:
                    fuzz = log.progress(method_name)

                    if method_name in self.Attach:

                        object_id = self.instance_service(method_name, pull='object')
                        if not object_id:
                            fuzz.status(color('Working...', YELLOW))
                            self.instance_service(method_name, dattach=True, start=True, fuzz=True)
                            object_id = self.instance_service(method_name, pull='object')

                        if object_id:
                            fuzz.success(color(str(self.instance_service(method_name, pull='object')), GREEN))
                            fuzz_result.update(
                                {method_name: {
                                    "available": True, "params": self.instance_service(method_name, pull='params'),
                                    "attach_params": self.instance_service(method_name, pull='attach_params')
                                }})

                        if not object_id:
                            for key in dparams:
                                for doptions in attach_options:
                                    params = {key: doptions}
                                    self.instance_service(
                                        method_name, dattach=True, params=params, attach_params=params,
                                        start=True, fuzz=True, multicall=True, multicallsend=False)

                            self.instance_service(
                                method_name, dattach=True, attach_params=params, start=True, fuzz=True,
                                multicall=True, multicallsend=True)
                            object_id = self.instance_service(method_name, pull='object')

                            if object_id:
                                fuzz.success(color(str(self.instance_service(method_name, pull='object')), GREEN))
                                fuzz_result.update(
                                    {method_name: {
                                        "available": True, "params": self.instance_service(method_name, pull='params'),
                                        "attach_params": self.instance_service(method_name, pull='attach_params')
                                    }})
                                continue

                            if not object_id:
                                fuzz_error = self.fuzzDB.get(method_name).get('sid').get('error')
                                fuzz.failure(color(json.dumps(fuzz_error), RED))
                                fuzz_result.update(
                                    {method_name: {
                                        "available": False, "code": fuzz_error.get('code'),
                                        "message": fuzz_error.get('message')}}
                                )

                    else:
                        object_id = self.instance_service(method_name, pull='object')
                        if not object_id:
                            fuzz.status(color('Working...', YELLOW))
                            self.instance_service(method_name, dattach=False, start=True, fuzz=True)
                            object_id = self.instance_service(method_name, pull='object')

                        if object_id:
                            fuzz.success(color(str(self.instance_service(method_name, pull='object')), GREEN))
                            fuzz_result.update(
                                {method_name: {
                                    "available": True, "params": self.instance_service(method_name, pull='params'),
                                    "attach_params": self.instance_service(method_name, pull='attach_params')
                                }})

                        if not object_id:
                            for key in dparams:
                                for doptions in attach_options:
                                    params = {key: doptions}
                                    self.instance_service(
                                        method_name, dattach=False, params=params, start=True, fuzz=True,
                                        multicall=True, multicallsend=False)

                            self.instance_service(
                                method_name, dattach=False, start=True, fuzz=True, multicall=True, multicallsend=True)

                            object_id = self.instance_service(method_name, pull='object')
                            if object_id:
                                fuzz.success(color(str(self.instance_service(method_name, pull='object')), GREEN))
                                fuzz_result.update(
                                    {method_name: {
                                        "available": True, "params": self.instance_service(method_name, pull='params'),
                                        "attach_params": self.instance_service(method_name, pull='attach_params')
                                    }})
                                continue

                            if not object_id:
                                fuzz_error = self.fuzzDB.get(method_name).get('sid').get('error')
                                fuzz.failure(color(json.dumps(fuzz_error), RED))
                                fuzz_result.update(
                                    {method_name: {
                                        "available": False, "code": fuzz_error.get('code'),
                                        "message": fuzz_error.get('message')}}
                                )

                self.instance_service(method_name="", list_all=True)
                # print(json.dumps(fuzz_result,indent=4))
                # print(json.dumps(self.fuzzDB,indent=4))
                # self.fuzzServiceDB = {} # Reset
                return

            else:
                log.failure('No such command "{}"'.format(msg))

        except KeyboardInterrupt:  # [Main TRY]
            return False

        return

    def dev_storage(self):

        query_args = {
            "method": "storage.getDeviceAllInfo",
            "params": None,
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            log.failure("\033[92m[\033[91mStorage: Device not found\033[92m]\033[0m")
            return

        if dh_data.get('result'):
            device_name = dh_data.get('params').get('info')[0].get('Name')

            method_name = 'devStorage'

            self.instance_service(method_name, params={"name": device_name}, start=True)
            object_id = self.instance_service(method_name, pull='object')
            if not object_id:
                return False

            query_args = {
                "method": "devStorage.getDeviceInfo",
                "params": None,
                "object": object_id,
            }

            dh_data = self.send_call(query_args)

            if not dh_data:
                if dh_data.get('result'):
                    dh_data = dh_data.get('params').get('device')  # [storage]
                    log.success("\033[92m[\033[91mStorage: \033[94m{}\033[91m\033[92m]\033[0m\n".format(
                        dh_data.get('Name', '(null)')))
                    log.info("Capacity: {}, Media: {}, Bus: {}, State: {}".format(
                        size(dh_data.get('Capacity', '(null)')),
                        dh_data.get('Media', '(null)'),
                        dh_data.get('BUS', '(null)'),
                        dh_data.get('State', '(null)'),
                    ))
                    log.info("Model: {}, SerialNo: {}, Firmware: {}".format(
                        dh_data.get(
                            'Module', '(null)') if self.DeviceClass == "NVR" else dh_data.get('Model', '(null)'),
                        dh_data.get(
                            'SerialNo', '(null)')if self.DeviceClass == "NVR" else dh_data.get('Sn', '(null)'),
                        dh_data.get('Firmware', '(null)'),
                    ))
                    for part in range(0, len(dh_data.get('Partitions'))):
                        tmp = dh_data.get('Partitions')[part]
                        log.info("{}, FileSystem: {}, Size: {}, Free: {}".format(
                            tmp.get('Name', '(null)'),
                            tmp.get('FileSystem', '(null)'),
                            size(tmp.get('Total', 0), si=True),
                            size(tmp.get('Remain', 0), si=True),
                        ))

            self.instance_service(method_name, stop=True)

    def get_encrypt_info(self):

        query_args = {
            "method": "Security.getEncryptInfo",
            "params": None,
        }

        dh_data = self.send_call(query_args)

        if not dh_data:
            log.failure("\033[92m[\033[91mEncrypt Info: Fail\033[92m]\033[0m")
            return

        if dh_data.get('result'):
            pub = dh_data.get('params').get('pub').split(",")
            log.success(
                "\033[92m[\033[91mEncrypt Info\033[92m]\033[0m\nAsymmetric:"
                " {}, Cipher: {}, Padding: {}, RSA Exp.: {}\nRSA Modulus:\n{}".format(
                    dh_data.get('params').get('asymmetric'),
                    '; '.join(dh_data.get('params').get('cipher', ["(null)"])),
                    '; '.join(dh_data.get('params').get('AESPadding', ["(null)"])),
                    pub[1].split(":")[1],
                    pub[0].split(":")[1],
                ))
            pubkey = RSA.construct((int(pub[0].split(":")[1], 16), int(pub[1].split(":")[1], 16)))
            print(pubkey.exportKey().decode('ascii'))

    def get_remote_info(self, msg):

        cmd = msg.split()

        if cmd[0] == 'device':

            query_args = {
                "method": "magicBox.getSoftwareVersion",
                "params": None,
            }
            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "magicBox.getProductDefinition",
                "params": None,
            }

            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "magicBox.getSystemInfo",
                "params": None,
            }

            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "magicBox.getMemoryInfo",
                "params": None,
            }

            dh_data = self.send_call(query_args, multicall=True, multicallsend=True)
            if not dh_data:
                return

            if dh_data.get(
                    'magicBox.getSoftwareVersion').get('result') and dh_data.get(
                    'magicBox.getProductDefinition').get('result'):
                tmp = dh_data.get('magicBox.getProductDefinition').get('params').get('definition')

                log.success(
                    "\033[92m[\033[91mSystem\033[92m]\033[0m\nVendor: {}, Build: {}, Version: {}\n"
                    "Device: {}, Web: {}, OEM: {}\nPackage: {}".format(
                        tmp.get('Vendor', '(null)'),
                        tmp.get('BuildDateTime', '(null)'),
                        dh_data.get(
                            'magicBox.getSoftwareVersion').get('params').get('version').get('Version', '(null)'),
                        tmp.get('Device', '(null)'),
                        tmp.get('WebVersion', '(null)'),
                        tmp.get('OEMVersion', '(null)'),
                        tmp.get('PackageBaseName', '(null)')
                        if tmp.get('PackageBaseName')
                        else tmp.get('ProductName', '(null)'),
                    ))

            if dh_data.get('magicBox.getSystemInfo').get('result'):
                tmp = dh_data.get('magicBox.getSystemInfo').get('params')
                log.success("\033[92m[\033[91mDevice\033[92m]\033[0m\nType: {}, CPU: {}, HW ver: {}, S/N: {}".format(
                    tmp.get('deviceType', '(null)'),
                    tmp.get('processor', '(null)'),
                    tmp.get('hardwareVersion', '(null)'),
                    tmp.get('serialNumber', '(null)'),
                ))

            if dh_data.get('magicBox.getMemoryInfo').get('result'):
                tmp = dh_data.get('magicBox.getMemoryInfo').get('params')
                log.success("\033[92m[\033[91mMemory\033[92m]\033[0m\nTotal: {}, Free: {}".format(
                    size(tmp.get('total', 0)),
                    size(tmp.get('free', 0))
                ))
            self.dev_storage()
            self.get_encrypt_info()

        elif cmd[0] == 'certificate':
            query_args = {
                "method": "CertManager.exportRootCert",
                "params": None,
            }

            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "CertManager.getSvrCertInfo",
                "params": None,
            }

            dh_data = self.send_call(query_args, multicall=True, multicallsend=True)
            if not dh_data:
                return

            if dh_data.get('CertManager.exportRootCert').get('result'):
                ca_cert = base64.decodebytes(
                    dh_data.get('CertManager.exportRootCert').get('params').get('cert').encode('latin-1')
                )
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert)
                # issuer = x509.get_issuer()
                # subject = x509.get_subject()

                log.success(
                    "\033[92m[\033[91mRoot Certificate\033[92m]\033[0m\n"
                    "\033[92m[\033[91mIssuer\033[92m]\033[0m\n"
                    "{}\n"
                    "\033[92m[\033[91mSubject\033[92m]\033[0m\n"
                    "{}\n"
                    "{}".format(
                        str(x509.get_issuer()).split("'")[1],
                        str(x509.get_subject()).split("'")[1],
                        ca_cert.decode('latin-1'),
                    ))

                log.success(
                    "\033[92m[\033[91mPublic Key\033[92m]\033[0m\n"
                    "{}".format(crypto.dump_publickey(crypto.FILETYPE_PEM, x509.get_pubkey()).decode('latin-1')))
                print('{:X}'.format(x509.get_pubkey().to_cryptography_key().public_numbers().n))
            else:
                log.failure(
                    "\033[92m[\033[91mRoot Certificate\033[92m]\033[0m\n{}".format(
                        color(dh_data.get('CertManager.exportRootCert').get('error'), LRED)))
                return False

            if dh_data.get('CertManager.getSvrCertInfo').get('result'):
                log.success("\033[92m[\033[91mServer Certificate\033[92m]\033[0m\n{}".format(
                    json.dumps(dh_data.get('CertManager.getSvrCertInfo'), indent=4),
                ))

        elif cmd[0] == 'dhp2p':

            query_args = {
                "method": "Nat.getTurnStatus",
                "params": None,
            }
            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "magicBox.getSystemInfo",
                "params": None,
            }

            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "configManager.getConfig",
                "params": {
                    "name": "_DHCloudUpgrade_",
                },
            }
            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "configManager.getConfig",
                "params": {
                    "name": "_DHCloudUpgradeRecord_",
                },
            }
            dh_data = self.send_call(query_args, multicall=True, multicallsend=True)
            if not dh_data:
                return

            if dh_data.get('Nat.getTurnStatus').get('result'):
                tmp = dh_data.get('Nat.getTurnStatus').get('params').get('Status')
                log.success("\033[92m[\033[91mDH DMSS P2P\033[92m]\033[0m\nEnable: {}, Status: {}, Detail: {}".format(
                    tmp.get('IsTurnChannel', '(null)'),
                    tmp.get('Status', '(null)'),
                    tmp.get('Detail', '(null)'),
                ))

            if dh_data.get('_DHCloudUpgradeRecord_').get('result') or dh_data.get('_DHCloudUpgrade_').get('result'):

                tmp = dh_data.get('_DHCloudUpgradeRecord_').get('params').get('table')
                tmp2 = dh_data.get('_DHCloudUpgrade_').get('params').get('table')
                log.success(
                    "\033[92m[\033[91mDH Cloud Firmware Upgrade\033[92m]\033[0m\n"
                    "Address: {}, Port: {}, ProxyAddr: {}, ProxyPort: {}\n"
                    "AutoCheck: {}, CheckInterval: {}, Upgrade: {}, downloadState: {}\n"
                    "LastVersion: {},\nLastSubVersion: {}\npackageId: {}".format(
                        tmp2.get('Address'),
                        tmp2.get('Port'),
                        tmp.get('ProxyAddr'),
                        tmp.get('ProxyPort'),
                        bool(tmp.get('AutoCheck')),
                        tmp.get('CheckInterval'),
                        bool(tmp.get('Upgrade')),
                        bool(tmp.get('downloadState')),
                        tmp.get('LastVersion'),
                        tmp.get('LastSubVersion'),
                        tmp.get('packageId'),
                    ))

            if dh_data.get('magicBox.getSystemInfo').get('result'):
                tmp = dh_data.get('magicBox.getSystemInfo').get('params')
                log.success(
                    "\033[92m[\033[91mDH Cloud Firmware ID\033[92m]\033[0m\n"
                    "Upgrade S/N: {}\n"
                    "Update S/N: {}".format(
                        tmp.get('updateSerialCloudUpgrade', '(null)'),
                        tmp.get('updateSerial', '(null)')
                    )
                )

    def delete_config(self, msg):
        cmd = msg.split()
        if len(cmd) != 2:
            log.info('{}'.format(help_all(msg=msg, usage='delete-config member')))

        key = cmd[1]
        method_name = 'configManager'
        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        query_args = {
            "method": "configManager.deleteConfig",
            "params": {
                "name": key,
            },
            "object": object_id,
        }
        log.info(f"Deleting member {key}")
        dh_data = self.send_call(query_args)
        if not dh_data:
            return
        print(json.dumps(dh_data, indent=4))

    def new_config(self, msg):
        """
        PoC for new non-existing configuration
        (instance_service() not really needed here, more as FYI for future)
        """

        cmd = msg.split()

        usage = {
            "show": "(Show config in script)",
            "set": "(Set config in device)",
            "get": "(Get config from device)",
            "del": "(Delete config in device)",
        }
        if len(cmd) == 1 or len(cmd) == 2 and cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        method_name = 'configManager'
        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')

        if cmd[1] == 'set' or cmd[1] == 'show':
            query_args = {
                "method": "configManager.setConfig",
                "params": {
                    "table": {
                        "Config": 31337,
                        "Enable": False,
                        "Description": "Just simple PoC",
                    },
                    "name": "Config_31337",
                },
                "object": object_id,
            }
            if cmd[1] == 'show':
                print(json.dumps(query_args, indent=4))
                return

            log.info("query: {} ".format(query_args))

            dh_data = self.send_call(query_args)
            if not dh_data:
                return
            print(json.dumps(dh_data, indent=4))

        elif cmd[1] == 'get':
            query_args = {
                "method": "configManager.getConfig",
                "params": {
                    "name": "Config_31337",
                },
                "object": object_id,
            }

            log.info("query: {} ".format(query_args))

            dh_data = self.send_call(query_args)
            if not dh_data:
                return

            print(json.dumps(dh_data, indent=4))

        elif cmd[1] == 'del':
            query_args = {
                "method": "configManager.deleteConfig",
                "params": {
                    "name": "Config_31337",
                },
                "object": object_id,
            }

            log.info("query: {} ".format(query_args))

            dh_data = self.send_call(query_args)
            if not dh_data:
                return

            print(json.dumps(dh_data, indent=4))

        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        self.instance_service(method_name, stop=True)

        return

    def set_ldap(self):
        """ LDAP test, seems not to be connecting """

        method_name = 'configManager'

        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        # https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
        # ldapsearch -h ldap.forumsys.com -w password -D "uid=tesla,dc=example,dc=com" -b "dc=example,dc=com"
        query_args = {
            "method": "configManager.setConfig",
            "params": {
                "name": "LDAP",
                "table": [
                    {
                        "AnonymousBind": False,
                        "BaseDN": "ou=scientists,dc=example,dc=com",
                        "BindDN": "uid=tesla,ou=scientists,dc=example,dc=com",
                        "BindPassword": "password",
                        "Enable": True,
                        "Filter": "",
                        "Port": 389,
                        "Server": "192.168.5.11",
                        # "Server": "ldap.forumsys.com",
                    }
                ],
            },
            "object": object_id,
        }

        dh_data = self.send_call(query_args)
        print('LDAP', dh_data)
        if not dh_data:
            return False

        self.instance_service(method_name, stop=True)

        return True

    def set_debug(self):

        # cmd = msg.split()

        method_name = 'configManager'

        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        query_args = {
            "method": "configManager.setConfig",
            "params": {
                "name": "Debug",
                "table": {
                    "PrintLogLevel": 0,
                    # "enable":True,
                },
            },
            "object": object_id,
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            return False

        log.success("PrintLogLevel 0: {}".format(dh_data.get('result')))

        query_args = {
            "method": "configManager.setConfig",
            "params": {
                "name": "Debug",
                "table": {
                    "PrintLogLevel": 6,
                    # "enable":True,
                },
            },
            "object": object_id,
        }

        dh_data = self.send_call(query_args)
        if not dh_data:
            return False

        log.success("PrintLogLevel 6: {}".format(dh_data.get('result')))

        self.instance_service(method_name, stop=True)

        return True

    def u_boot(self, msg):

        cmd = msg.split()

        usage = {
            "printenv": "(Get all possible env config)",
            "setenv": "<variable> <value> (not working)",
            "getenv": "<variable>"
        }
        if len(cmd) == 1:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        method_name = 'magicBox'

        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        if cmd[1] == 'setenv':
            if not len(cmd) == 4:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            query_args = {
                "method": "magicBox.setEnv",
                "params": {
                    "name": cmd[2],
                    "value": cmd[3],
                    # "name":"loglevel",
                    # "value":"5",
                },
                "object": object_id,
            }

        #
        # Here we looking for the most common U-Boot enviroment variables, if you miss any, add it to the list here.
        #
        elif cmd[1] == 'printenv':  # OK: IPC/VTH/VTO, NOT: NVR

            query_args = {
                "method": "magicBox.getBootParameter",
                "params": {
                    "names": [
                        "algorithm",
                        "appauto",
                        "AUTHCODE",
                        "authcode",
                        "AUTHKEY",
                        "autogw",
                        "autolip",
                        "autoload",
                        "autonm",
                        "autosip",
                        "baudrate",
                        "bootargs",
                        "bootcmd",
                        "bootdelay",
                        "bootfile",
                        "BSN",
                        "coremnt",
                        "COUNTRYCODE",
                        "da",
                        "da0",
                        "dc",
                        "debug",
                        "devalias",
                        "DeviceID",
                        "deviceid",
                        "DeviceSecret",
                        "DEVID",
                        "devname",
                        "devOEM",
                        "dh_keyboard",
                        "dk",
                        "dl",
                        "dp",
                        "dr",
                        "DspMem",
                        "du",
                        "dvname",
                        "dw",
                        "encrypbackup",
                        "eth1addr",
                        "ethact",
                        "ethaddr",
                        "ext1",
                        "ext2",
                        "ext3",
                        "ext4",
                        "ext5",
                        "fd",
                        "fdtaddr",
                        "fileaddr",
                        "filesize",
                        "gatewayip",
                        "HWID",
                        "hwidEx",
                        "HWMEM",
                        "hxapppwd",
                        "icrtest",
                        "icrtype",
                        "ID",
                        "intelli",
                        "ipaddr",
                        "key",
                        "licence",
                        "loglevel",
                        "logserver",
                        "MarketArea",
                        "mcuDebug",
                        "mcuHWID",
                        "mdcmdline",
                        "Mem512M",
                        "mmc_root",
                        "mp_autotest",
                        "nand_root",
                        "netmask",
                        "netretry",
                        "OEI",
                        "partitions",
                        "PartitionVer",
                        "peripheral",
                        "productDate",
                        "ProductKey",
                        "ProductSecret",
                        "quickstart",
                        "randomcode",
                        "restore",
                        "SC",
                        "ser_debug",
                        "serverip",
                        "setargs_mmc",
                        "setargs_nand",
                        "setargs_spinor",
                        "SHWID",
                        "Speripheral",
                        "spinand_root",
                        "spinor_root",
                        "stderr",
                        "stdin",
                        "stdout",
                        "sysbackup",
                        "SysMem",
                        "tftptimeout",
                        "tk",
                        "TracingCode",
                        "tracode",
                        "uid",
                        "up",
                        "updatetimeout",
                        "UUID",
                        "vendor",
                        "ver",
                        "Verif_Code",
                        "verify",
                        "videodebug",
                        "watchdog",
                        "wifiaddr",
                        "COUNTRYCODE",

                        "HWID_ORG",  # MCW
                    ],
                },
                "object": object_id,
            }

        elif cmd[1] == 'getenv':
            if not len(cmd) == 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True
            # method = "magicBox.getEnv"  # should be
            method = "magicBox.getBootParameter"  # working too
            query_args = {
                "method": method,
                "params": {
                    "names": [cmd[2]],  # needed for magicBox.getBootParameter
                    # "name": cmd[2],  # needed for magicBox.getEnv
                },
                "object": object_id,
            }
        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        dh_data = self.send_call(query_args, errorcodes=True)
        if not dh_data:
            return False
        if dh_data.get('result'):
            print(json.dumps(dh_data, indent=4))
        elif not dh_data.get('result'):
            log.failure('Error: {}'.format(dh_data.get('error')))

        self.instance_service(method_name, stop=True)

        return

    #
    # tcpdump network capture from remote device
    #
    def network_sniffer_manager(self, msg):

        cmd = msg.split()

        usage = {
            "start": {
                "<nic> <path>": "[Wireshark capture filter syntax]"
            },
            "stop": "(stop remote pcap)",
            "info": "(info about remote pcap)"
        }
        if len(cmd) == 1 or cmd[1] == 'start' and not len(cmd) >= 4 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        method_name = 'NetworkSnifferManager'
        if not self.instance_service(method_name, pull='object'):
            self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        self.dh_sniffer_nic = 'eth0'

        # dh_sniffer_nic = "eth0"
        # dh_sniffer_path = "/nfs"
        # dh_sniffer_filter = ""
        # dh_sniffer_filter = \
        # "not host 192.168.57.20 and not host 192.168.57.7 and not host 192.168.57.167 and not host 192.168.57.27"

        if cmd[1] == 'start':

            if not self.interim_remote_diagnose("diag nfs status"):
                log.failure("NFS must be mounted with: diag nfs mount")
                return False

            self.dh_sniffer_nic = cmd[2]
            dh_sniffer_path = cmd[3]
            dh_sniffer_filter = ''
            if len(cmd) > 3:
                dh_sniffer_filter = ' '.join(cmd[4:])

            query_args = {
                "method": "NetworkSnifferManager.start",
                "params": {
                    "networkCard": self.dh_sniffer_nic,
                    "path": dh_sniffer_path,
                    "saveType": "Wireshark/Tcpdump",
                    "filter": dh_sniffer_filter,
                },
                "object": object_id,
            }

            dh_data = self.send_call(query_args)
            if not dh_data:
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                return False
            # print(json.dumps(dh_data,indent=4))

            if not dh_data.get('result'):
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                self.instance_service(method_name, stop=True)
                return False

            self.networkSnifferID = dh_data.get('params').get('networkSnifferID')
            log.info("({}) Start: ID: {}, NIC: {}, Path: {}, Filter: {}".format(
                cmd[0],
                self.networkSnifferID,
                query_args.get('params').get('networkCard'),
                query_args.get('params').get('path'),
                query_args.get('params').get('filter'),
            ))

        elif cmd[1] == 'info':

            query_args = {
                "method": "NetworkSnifferManager.getSnifferInfo",
                "params": {
                    "condition": {
                        "NetworkCard": self.dh_sniffer_nic,
                    },
                },
                "object": object_id,
            }

            dh_data = self.send_call(query_args)
            if not dh_data:
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                return False

            if not dh_data.get('result'):
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                self.instance_service(method_name, stop=True)
                return False

            sniffer_infos = dh_data.get('params').get('snifferInfos')
            if not len(sniffer_infos):
                log.info("No remote pcap running")
                return False

            self.networkSnifferID = sniffer_infos[0].get('NetworkSnifferID')
            self.networkSnifferPath = sniffer_infos[1].get('Path')
            log.info("({}) Info: ID: {}, Path: {}".format(cmd[0], self.networkSnifferID, self.networkSnifferPath))

            return True

        elif cmd[1] == 'stop':

            if not self.network_sniffer_manager("pcap info"):
                return False

            query_args = {
                "method": "NetworkSnifferManager.stop",
                "params": {
                    "networkSnifferID": self.networkSnifferID,
                },
                "object": object_id,
            }

            dh_data = self.send_call(query_args)
            if not dh_data:
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                return False

            if not dh_data.get('result'):
                log.failure(color("{}: {}".format(query_args.get('method'), dh_data), LRED))
                self.instance_service(method_name, stop=True)
                return False

            self.instance_service(method_name, stop=True)
            log.info("({}) Stopped: ID: {}, Path: {}".format(cmd[0], self.networkSnifferID, self.networkSnifferPath))

        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))

        return

    #
    # Debug of remote device
    #
    def interim_remote_diagnose(self, msg):

        cmd = msg.split()

        usage = {
            "nfs": {
                "status": "(Check if NFS mounted)",
                "mount": "[<server host> /<server path>]",
                "umount": "(Umount NFS)",
            },
            "usb": {
                "get": "(Not done yet)",
                "set": "(Not done yet)",
            },
            "pcap": {
                "start": "(Start capture)",
                "stop": "(Stop capture)",
                "filter": "<get> | <set> <lo|eth0|eth2> <host>",
            },
            "coredump": {
                "start": "(Start coredump support)",
                "stop": "(Stop coredump support)",
            },
            "logs": {
                "start": "(Start redirect logs to NFS)",
                "stop": "(Stop redirect logs to NFS)",
            }
        }
        if len(cmd) < 2 or len(cmd) == 3 and cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        if not self.check_for_service('InterimRemoteDiagnose'):
            return False

        if cmd[1] == 'nfs':

            if not len(cmd) >= 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            if cmd[2] == 'status':

                query_args = {
                    "method": "InterimRemoteDiagnose.getConfig",
                    "params": {
                        "name": "InterimRDNfs",
                    },
                }
                dh_data = self.send_call(query_args)
                if dh_data:
                    dh_data = dh_data.get('params').get('DebugConfig')
                    log.info(
                        "NFS Directory: {}, Serverip: {}, Enable: {}".format(
                            dh_data.get('Directory'), dh_data.get('Serverip'), dh_data.get('Enable'))
                    )

                # {"result":true,"params":{"conn":true},"session":2103981993,"id":4}
                # {"result":true,"params":{"conn":false},"session":2103981993,"id":4}
                query_args = {
                    "method": "InterimRemoteDiagnose.testNfsStatus",
                    "params": {
                    },
                }
                dh_data = self.send_call(query_args)
                if dh_data:
                    log.info("NFS connected: {}".format(dh_data.get('params').get('conn')))
                    return dh_data.get('params').get('conn')

                log.failure('NFS status')
                return False

            elif cmd[2] == 'mount' or cmd[2] == 'umount':

                if len(cmd) >= 4:
                    if not check_ip(cmd[3]):
                        log.failure('"{}" is not valid host'.format(cmd[3]))
                        return False
                    if len(cmd) == 5 and not cmd[4][0] == '/':
                        log.failure('path must start with "/"'.format(cmd[4]))
                        return False

                query_args = {
                    "method": "InterimRemoteDiagnose.getConfig",
                    "params": {
                        "name": "InterimRDNfs",
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                debug_config = dh_data.get('params').get('DebugConfig')

                debug_config['Enable'] = True if cmd[2] == 'mount' else False
                debug_config.update({"Serverip": cmd[3] if len(cmd) >= 4 else debug_config.get('Serverip')})
                debug_config.update({"Directory": cmd[4] if len(cmd) == 5 else debug_config.get('Directory')})

                query_args = {
                    "method": "InterimRemoteDiagnose.setConfig",
                    "params": {
                        "name": "InterimRDNfs",
                        "DebugConfig": {
                            # Default config
                            # "Directory":"/c/public_dev",
                            # "Enable":False,
                            # "Serverip":"10.33.12.137"
                        },
                    },
                }
                query_args.get('params').get('DebugConfig').update(debug_config)

                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("NFS {}: {}".format('mount' if cmd[2] == 'mount' else 'umount', dh_data.get('result')))
                return True
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

        elif cmd[1] == 'usb':

            if not len(cmd) == 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            if cmd[2] == 'get':

                # {"result":true,"params":{"UStoragePosition":['/dev/sdb1', '/dev/sdc1']},"session":1217107065,"id":4}
                # {"result":true,"params":{"UStoragePosition":null},"session":1413317462,"id":4}
                query_args = {
                    "method": "InterimRemoteDiagnose.getUStoragePosition",
                    "params": {
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info(
                    "USB Storage: {}".format(
                        dh_data.get('params').get('UStoragePosition')
                        if dh_data.get('params').get('UStoragePosition') else "Not found")
                )
                return True
            elif cmd[2] == 'set':
                # error: {'code': 268959743, 'message': 'Unknown error! error code was not set in service!'}
                query_args = {
                    "method": "InterimRemoteDiagnose.setUStoragePosition",
                    "params": {
                        "UStoragePosition": "/dev/sdb1",
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("USB Storage: {}".format(dh_data))
                return True
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False

        elif cmd[1] == 'pcap':

            if not len(cmd) >= 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            if cmd[2] == 'filter':
                if not len(cmd) >= 4:
                    log.info('{}'.format(help_all(msg=msg, usage=usage)))
                    return False

                if cmd[3] == 'get':
                    query_args = {
                        "method": "InterimRemoteDiagnose.getConfig",
                        "params": {
                            "name": "InterimRDNetFilter",
                        },
                    }
                    dh_data = self.send_call(query_args)
                    if not dh_data:
                        return False
                    log.info("PCAP Filter: {}".format(dh_data.get('params').get('debug_config')))
                    return True

                elif cmd[3] == 'set':

                    #
                    # Might be more dh_data in the future, read and update only what we know
                    # Leave possible other untouched
                    #

                    query_args = {
                        "method": "InterimRemoteDiagnose.getConfig",
                        "params": {
                            "name": "InterimRDNetFilter",
                        },
                    }
                    dh_data = self.send_call(query_args)
                    if not dh_data:
                        return False

                    pcap_iface = 'eth0'
                    pcap_filter_ip = ''

                    # Default
                    # Name = 'eth0'
                    # FilterIP = '10.33.12.137'
                    # FilterPort = '37777'

                    debug_config = dh_data.get('params').get('DebugConfig')
                    debug_config.update({"FilterIP": pcap_filter_ip})
                    # debug_config.update({"FilterPort":FilterPort})	# Cannot be changed from 37777
                    debug_config.update({"Name": pcap_iface})

                    query_args = {
                        "method": "InterimRemoteDiagnose.setConfig",
                        "params": {
                            "name": "InterimRDNetFilter",
                            "DebugConfig": debug_config,
                        },
                    }
                    dh_data = self.send_call(query_args)
                    if not dh_data:
                        return False
                    log.info("PCAP Filter: {}".format(debug_config))
                    return True

            elif cmd[2] == 'start':

                if not self.interim_remote_diagnose("diag nfs status"):
                    log.failure("NFS must be mounted with: diag nfs mount")
                    return False

                query_args = {
                    "method": "InterimRemoteDiagnose.getConfig",
                    "params": {
                        "name": "InterimRDNetFilter",
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False

                log.info("PCAP Filter: {}".format(dh_data.get('params').get('debug_config')))

                query_args = {
                    # {"result":true,"params":null,"session":336559066,"id":4}
                    "method": "InterimRemoteDiagnose.startRemoteCapture",
                    "params": {
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("PCAP Start: {}".format(dh_data.get('result')))
                return True

            elif cmd[2] == 'stop':
                query_args = {
                    # {"result":true,"params":null,"session":468902923,"id":4}
                    "method": "InterimRemoteDiagnose.stopRemoteCapture",
                    "params": {
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("PCAP Stop: {}".format(dh_data.get('result')))
                return True
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

        elif cmd[1] == 'coredump':

            if not self.args.force:
                log.failure("({}) will reboot NVR (force with -f)".format(cmd[1]))
                return False

            if not len(cmd) >= 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            if cmd[2] == 'start' or cmd[2] == 'stop':

                query_args = {
                    "method": "InterimRemoteDiagnose.setConfig",
                    "params": {
                        "name": "InterimRDCoreDump",
                        "DebugConfig": {
                            "Enable": True if cmd[2] == 'start' else False,
                        },
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("CoreDump {}: {}".format("Start" if cmd[2] == 'start' else "Stop", dh_data.get('result')))
                return True
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return False

        elif cmd[1] == 'logs':

            if not len(cmd) == 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

            if not self.interim_remote_diagnose("diag nfs status"):
                log.failure("NFS must be mounted")
                return False

            if cmd[2] == 'start' or cmd[2] == 'stop':

                query_args = {
                    "method": "InterimRemoteDiagnose.setConfig",
                    "params": {
                        "name": "InterimRDPrint",
                        "DebugConfig": {
                            "AlwaysEnable": False,
                            "OnceEnable": True if cmd[2] == 'start' else False,
                            "PrintLevel": 6
                        },
                    },
                }
                dh_data = self.send_call(query_args)
                if not dh_data:
                    return False
                log.info("Logs {}: {}".format("Start" if cmd[2] == 'start' else "Stop", dh_data.get('result')))
                return True
            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True

        else:
            log.failure('No such command: {}'.format(msg))
            # log.info('{}'.format(help_all(msg=msg,usage=usage)))
            return True

    def net_app(self, msg, callback=False):

        #
        # Should need to have events subscribed
        #
        if callback:
            print(json.loads(msg, indent=4))
            return True

        cmd = msg.split()
        dh_data = None
        nic = None
        net_resource_stat = None

        usage = {
            "info": "(Network Information)",
            "wifi": {
                "enable": "(enable adapter)",
                "disable": "(disable adapter)",
                "scan": "(scan for WiFi AP)",
                "conn": "<SSID> <key>",
                "disc": "(disconnect from WiFi AP)",
                "reset": "(reset WiFi settings to default)",
            },
            "upnp": {
                "status": "(show UPnP status)",
                "enable": "[all] (enable UPnP)",
                "disable": "[all] (disable UPnP)"
            }
        }

        if not len(cmd) >= 2 or cmd[1] == '-h':
            log.info('{}'.format(help_all(msg=msg, usage=usage)))
            return True

        method_name = 'netApp'

        if not self.instance_service(method_name, pull='object'):
            self.instance_service(method_name, start=True)

        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        query_args = {
            "method": "netApp.getNetInterfaces",
            "params": {
            },
            "object": object_id,
        }
        net_interface = self.send_call(query_args)

        if cmd[1] == 'wifi':

            if not len(cmd) >= 3 or cmd[1] == '-h':
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                self.instance_service(method_name, stop=True)
                return True

            wireless_nic = False

            for nic in net_interface.get('params').get('netInterface'):
                if nic.get('Type') == 'Wireless':
                    wireless_nic = nic.get('Name')

            if not wireless_nic:
                log.failure("No WiFi adapter available")
                return False

            auth_encryption = {
                "00": "Off",
                "01": "WEP-OPEN",
                "11": "WEP-SHARED",
                "32": "WPA-PSK-TKIP",
                "33": "WPA-PSK-TKIP+AES",
                "34": "WPA-PSK-TKIP+AES",
                "42": "WPA2-TKIP",
                "52": "WPA2-PSK-TKIP",
                "53": "WPA2-PSK-AES",
                "54": "WPA2-PSK-TKIP+AES",
                "72": "WPA/WPA2-PSK-TKIP",
                "73": "WPA/WPA2-PSK-AES",
                "74": "WPA/WPA2-PSK-TKIP+AES",
            }
            link_mode = {
                "0": "Auto",
                "1": "Ad-hoc",
                "2": "Infrastructure",
            }

            if len(cmd) == 3 and cmd[2] == 'scan':

                query_args = {
                    "method": "netApp.scanWLanDevices",
                    "params": {
                        "Name": wireless_nic,
                        "SSID": "",
                    },
                    "object": object_id,
                }
                dh_data = self.send_call(query_args)
                if not dh_data.get('params').get('wlanDevice'):
                    log.failure("No WiFi available")
                    return False

                wlan_device = dh_data.get('params').get('wlanDevice')
                for wifi_ap in wlan_device:
                    log.success(
                        "BSSID: {} RSSI: {} Strength: {} Quality: {} Connected: {} SSID: {}\n"
                        "MaxBitRate: {} Mbit NetWorkType: {} Connect Mode: {} Authorize Mode: {}".format(
                            color(wifi_ap.get('BSSID'), GREEN),
                            color(wifi_ap.get('RSSIQuality'), GREEN),
                            color(wifi_ap.get('Strength'), GREEN),
                            color(wifi_ap.get('LinkQuality'), GREEN),
                            color(bool(wifi_ap.get('ApConnected')), GREEN if wifi_ap.get('ApConnected') else RED),
                            color(wifi_ap.get('SSID'), GREEN),
                            color(str(int(wifi_ap.get('ApMaxBitRate')) / 1000000).split('.')[0], GREEN),

                            color(wifi_ap.get('ApNetWorkType'), GREEN),
                            color(link_mode.get(str(wifi_ap.get('link_mode'))), GREEN),
                            color(auth_encryption.get(
                                str(wifi_ap.get('AuthMode')) + str(wifi_ap.get('EncrAlgr')), "UNKNOWN"), GREEN)
                        ))

            elif len(cmd) == 5 and cmd[2] == 'conn' or len(cmd) == 3 and cmd[2] in [
                    'enable', 'disable', 'conn', 'disc', 'reset']:

                if cmd[2] == 'conn' and len(cmd) == 5:

                    query_args = {
                        "method": "netApp.scanWLanDevices",
                        "params": {
                            "Name": wireless_nic,
                            "SSID": cmd[3],
                        },
                        "object": object_id,
                    }
                    self.send_call(query_args, multicall=True)

                query_args = {
                    "method": "configManager.getDefault" if cmd[2] == 'reset' else "configManager.getConfig",
                    "params": {
                        "name": "WLan",
                    },
                }
                dh_data = self.send_call(query_args, multicall=True, multicallsend=True)
                if not dh_data:
                    log.failure("(WLan) {}".format(dh_data))
                    return False

                wlan = dh_data.get('WLan').get('params').get('table').get(wireless_nic)

                if len(cmd) == 3 and cmd[2] == 'conn' or len(cmd) == 3 and cmd[2] == 'disc':
                    if wlan.get('SSID'):
                        if nic.get('ConnStatus') == 'Connected' and cmd[2] == 'conn':
                            log.failure("Already Connected")
                            return False
                        elif nic.get('ConnStatus') == 'Disconn' and cmd[2] == 'disc':
                            log.failure("Already Disconnected")
                            return False
                        elif not wlan.get('Enable'):
                            log.failure("WiFi disabled")
                            return False
                        wlan['ConnectEnable'] = True if cmd[2] == 'conn' else False
                    else:
                        log.failure("Wireless not configured")
                        return False
                elif len(cmd) == 3 and cmd[2] == 'enable' or len(cmd) == 3 and cmd[2] == 'disable':
                    if wlan.get('Enable') and cmd[2] == 'enable':
                        log.failure("Already Enabled")
                        return False
                    elif not wlan.get('Enable') and cmd[2] == 'disable':
                        log.failure("Already Disabled")
                        return False
                    wlan['Enable'] = True if cmd[2] == 'enable' else False

                if cmd[2] == 'conn' and len(cmd) == 5:
                    if not dh_data.get('netApp.scanWLanDevices').get('result'):
                        log.failure('Wrong SSID and/or AP not accessible')
                        return False

                    wifi_ap = dh_data.get('netApp.scanWLanDevices').get('params').get('wlanDevice')[0]

                    wlan['Encryption'] = auth_encryption.get(
                        str(wifi_ap.get('AuthMode')) + str(wifi_ap.get('EncrAlgr'))) if cmd[2] == 'conn' else 'Off'
                    wlan['link_mode'] = link_mode.get(str(wifi_ap.get('link_mode')))
                    wlan['ConnectEnable'] = True if cmd[2] == 'conn' else False
                    wlan['KeyFlag'] = True if cmd[2] == 'conn' else False
                    wlan['SSID'] = wifi_ap.get('SSID') if cmd[2] == 'conn' else ''
                    wlan['Keys'][0] = cmd[4] if cmd[2] == 'conn' else 'abcd'

                query_args = {
                    "method": "configManager.setConfig",
                    "params": {
                        "name": "WLan",
                        "table": dh_data.get('WLan').get('params').get('table'),
                    },
                }

                dh_data = self.send_call(query_args)

                if not dh_data or not dh_data.get('result'):
                    log.failure('TimeOut for "{}" (wrong pwd?)'.format(wlan.get('SSID')))
                    log.failure("dh_data: {}".format(dh_data))
                    return False

                if cmd[2] == 'conn' and wlan.get('Enable')\
                        or cmd[2] == 'enable' and wlan.get('SSID') and wlan.get('ConnectEnable'):
                    conn = log.progress("Status")

                    while True:
                        query_args = {
                            "method": "netApp.getNetInterfaces",
                            "params": {
                            },
                            "object": object_id,
                        }
                        dh_data = self.send_call(query_args)

                        for nic in dh_data.get('params').get('net_interface'):
                            if not nic.get('Type') == 'Wireless':
                                continue
                            conn.status(nic.get('ConnStatus'))
                            if nic.get('ConnStatus') == 'Connected':
                                conn.success('Connected')
                                return True
                            time.sleep(1)
                else:
                    self.instance_service(method_name, stop=True)
                    log.success("Success")

            # ConfigManager.getConfig("AccessPoint")
            # ConfigManager.getConfig("WLan")

            else:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                return True
        elif cmd[1] == 'info':

            for nic in net_interface.get('params').get('netInterface'):

                net_appmethod = {
                    "netApp.getNetDataStat",
                    "netApp.getNetResourceStat",
                    "netApp.getCaps",
                }

                for method in net_appmethod:
                    query_args = {
                        "method": method,
                        "params": {
                            "Name": nic.get('Name'),
                        },
                        "object": object_id,
                    }
                    self.send_call(query_args, multicall=True)

                query_args = {
                    "method": "configManager.getConfig",
                    "params": {
                        "name": "Network",
                    },
                }

                dh_data = self.send_call(query_args, multicall=True, multicallsend=True)
                # print(json.dumps(dh_data,indent=4))

                net_data_stat = dh_data.get('netApp.getNetDataStat').get('params')
                net_resource_stat = dh_data.get('netApp.getNetResourceStat').get('params')
                nic_iface = dh_data.get('Network').get('params').get('table').get(nic.get('Name'))

                link_info = "Link support long PoE: {}, connection: {}, speed: {}".format(
                    nic.get('SupportLongPoE'),
                    nic.get('Type') if nic.get('Type') == 'Wireless' else 'Wired',
                    nic.get('Speed'),
                )

                log.success(
                    "\033[92m[\033[91m{}\033[92m]\033[0m {}{}\ndhcp: {} dns: [{}] mtu: {}\n"
                    "inet {} netmask {} gateway {}\nether {} txqueuelen {}\n"
                    "RX packets {} bytes {} ({}) util {} Kbps\n"
                    "RX errors {} dropped {} overruns {} frame {}\n"
                    "TX packets {} bytes {} ({}) util {} Kbps\n"
                    "TX errors {} dropped {} carrier {} collisions {}\n{}".format(
                        nic.get('Name'),
                        color(nic.get('ConnStatus'), GREEN if nic.get('ConnStatus') == 'Connected' else RED),
                        color(
                            " (SSID: {})".format(nic.get('ApSSID'))
                            if nic.get('ConnStatus') == 'Connected' and nic.get('Type') == 'Wireless' else '',
                            LBLUE),

                        nic_iface.get('DhcpEnable'),
                        ', '.join(str(x) for x in nic_iface.get('DnsServers')),
                        nic_iface.get('MTU'),
                        nic_iface.get('IPAddress'),
                        nic_iface.get('SubnetMask'),
                        nic_iface.get('DefaultGateway'),
                        nic_iface.get('PhysicalAddress'),

                        net_data_stat.get('Transmit').get('txqueuelen'),
                        net_data_stat.get('Receive').get('packets'),
                        net_data_stat.get('Receive').get('bytes'),
                        size(net_data_stat.get('Receive').get('bytes')),
                        net_data_stat.get('Receive').get('speed'),

                        net_data_stat.get('Receive').get('errors'),
                        net_data_stat.get('Receive').get('droped'),
                        net_data_stat.get('Receive').get('overruns'),
                        net_data_stat.get('Receive').get('frame'),

                        net_data_stat.get('Transmit').get('packets'),
                        net_data_stat.get('Transmit').get('bytes'),
                        size(net_data_stat.get('Transmit').get('bytes')),
                        net_data_stat.get('Transmit').get('speed'),

                        net_data_stat.get('Transmit').get('errros'),  # consistent.. d0h!
                        net_data_stat.get('Transmit').get('droped'),
                        net_data_stat.get('Transmit').get('collisions'),
                        net_data_stat.get('Transmit').get('txqueuelen'),
                        link_info,
                    ))

            net_resource_info = \
                "IP Channel In: {}, Net Capability: {}, Net Remain: {}\n" \
                "Remote Preview: {}, Send Capability: {}, Send Remain {}".format(
                    net_resource_stat.get('IPChanneIn'),
                    net_resource_stat.get('NetCapability'),
                    net_resource_stat.get('NetRemain'),
                    net_resource_stat.get('RemotePreview'),
                    net_resource_stat.get('RemoteSendCapability'),
                    net_resource_stat.get('RemoteSendRemain'),
                )

            log.success("\033[92m[\033[91mInfo\033[92m]\033[0m default nic: {}, hostname: {}, domain: {}\n{}".format(
                dh_data.get('Network').get('params').get('table').get('DefaultInterface'),
                dh_data.get('Network').get('params').get('table').get('Hostname'),
                dh_data.get('Network').get('params').get('table').get('Domain'),
                net_resource_info,
            ))

            self.instance_service(method_name, stop=True)

        elif cmd[1] == 'upnp':

            if not len(cmd) == 3:
                log.info('{}'.format(help_all(msg=msg, usage=usage)))
                self.instance_service(method_name, stop=True)
                return False

            query_args = {
                "method": "netApp.getUPnPStatus",
                "params": None,
                "object": object_id,
            }
            self.send_call(query_args, multicall=True)

            query_args = {
                "method": "configManager.getConfig",
                "params": {
                    "name": "UPnP",
                },
            }
            dh_data = self.send_call(query_args, multicall=True, multicallsend=True)

            if not dh_data.get('netApp.getUPnPStatus').get('result') or not dh_data.get('UPnP').get('result'):
                log.failure('UPnP service not supported')
                return False

            if len(cmd) == 3 and cmd[2] == 'status':

                upnp_status = dh_data.get('netApp.getUPnPStatus').get('params')
                upnp_table = dh_data.get('UPnP').get('params').get('table')
                upnp_map = ''

                for MapTable in range(0, len(upnp_table.get('MapTable'))):
                    upnp_map += "Enable: {} Internal Port: {:<6} External Port: {:<6} " \
                                "Protocol: {}:{} ServiceName: {:<4} Status: {}\n".format(
                                    upnp_table.get('MapTable')[MapTable].get('Enable'),
                                    upnp_table.get('MapTable')[MapTable].get('InnerPort'),
                                    upnp_table.get('MapTable')[MapTable].get('OuterPort'),
                                    upnp_table.get('MapTable')[MapTable].get('Protocol'),
                                    upnp_table.get('MapTable')[MapTable].get('ServiceType'),
                                    upnp_table.get('MapTable')[MapTable].get('ServiceName'),
                                    color(
                                        upnp_status.get('PortMapStatus')[MapTable],
                                        GREEN if upnp_status.get('PortMapStatus')[MapTable] == 'Failed' else RED
                                    ))

                log.success(
                    "\033[92m[\033[91mUPnP\033[92m]\033[0m\n"
                    "Enable: {}, Mode: {}, Device Discover: {}\n"
                    "Status: {}, Working: {}, Internal IP: {}, external IP: {}\n"
                    "\033[92m[\033[91mMaps\033[92m]\033[0m\n{}".format(
                        color(upnp_table.get('Enable'), RED if upnp_table.get('Enable') else GREEN),
                        upnp_table.get('Mode'),
                        upnp_table.get('StartDeviceDiscover'),
                        color(upnp_status.get('Status'), RED if upnp_status.get('Working') else GREEN),
                        color(upnp_status.get('Working'), RED if upnp_status.get('Working') else GREEN),
                        upnp_status.get('InnerAddress'),
                        upnp_status.get('OuterAddress'),
                        upnp_map,
                    ))

            elif len(cmd) >= 3 and cmd[2] == 'disable' or cmd[2] == 'enable':

                query_args = {
                    "method": "configManager.getConfig",
                    "params": {
                        "name": "UPnP",
                    },
                }
                dh_data = self.send_call(query_args)

                upnp_config = dh_data.get('params').get('table')

                if not upnp_config.get('Enable') and cmd[2] == 'disable'\
                        or upnp_config.get('Enable') and cmd[2] == 'enable':
                    log.failure("UPnP already {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))
                    return False

                upnp_config['Enable'] = False if cmd[2] == 'disable' else True

                if len(cmd) == 4 and cmd[3] == 'all':
                    for dh_map in range(0, len(upnp_config.get('MapTable'))):
                        upnp_config['MapTable'][dh_map]['Enable'] = False if cmd[2] == 'disable' else True

                query_args = {
                    "method": "configManager.setConfig",
                    "params": {
                        "name": "UPnP",
                        "table": upnp_config,
                    },
                }
                dh_data = self.send_call(query_args)

                if dh_data.get('result'):
                    log.success("UPnP {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))
                else:
                    log.failure("UPnP NOT {}".format('disabled' if cmd[2] == 'disable' else 'enabled'))

            else:
                log.failure("{} {} {}".format(cmd[0], cmd[1], usage.get(cmd[1], '(No help defined)')))
                return False

        else:
            log.info('{}'.format(help_all(msg=msg, usage=usage)))

        self.instance_service(method_name, stop=True)

        return

    def dlog(self, msg):

        cmd = msg.split()

        method_name = 'log'

        self.instance_service(method_name, start=True)
        object_id = self.instance_service(method_name, pull='object')
        if not object_id:
            return False

        dlog_count = 20

        if len(cmd) == 2:
            try:
                dlog_count = int(cmd[1])
            except ValueError:
                log.failure('({}) not valid number'.format(cmd[1]))
                return False

        query_args = {
            "method": "global.getCurrentTime",
            "params": None,
        }

        dh_data = self.send_call(query_args)
        if not dh_data.get('result'):
            log.failure('{} Failed'.format(query_args.get('method')))
            return False

        query_args = {
            "method": "log.startFind",
            "params": {
                "condition": {
                    "StartTime": "1970-01-01 00:00:00",  # Lets start from the beginning ,)
                    "EndTime": dh_data.get('params').get('time'),
                    "Translate": True,
                    "Order": "Descent",  # ok
                    "Types": "",
                },
            },
            "object": object_id,
        }
        dh_data = self.send_call(query_args)
        if not dh_data.get('result'):
            log.failure('{} Failed'.format(query_args.get('method')))
            return False

        dlog_token = dh_data.get('params').get('token')

        query_args = {
            "method": "log.getCount",
            "params": {
                "token": dlog_token,
            },
            "object": object_id,
        }
        dh_data = self.send_call(query_args)
        if not dh_data or not dh_data.get('result'):
            log.failure('{} Failed'.format(query_args.get('method')))
            return False

        query_args = {
            "method": "log.doSeekFind",
            "params": {
                "token": dlog_token,
                "offset": 0,
                "count": dlog_count,
            },
            "object": object_id,
        }
        dh_data = self.send_call(query_args)
        if not dh_data.get('result'):
            log.failure('{} Failed'.format(query_args.get('method')))
            return False

        dlogs = dh_data.get('params').get('items')
        found = dh_data.get('params').get('found')

        log.info('Found: {}'.format(found))

        for dlog in dlogs:
            print('{}Detail: {}\nUser: {}, Device: {}, Type: {}, Level: {}'.format(
                help_msg(dlog.get('Time')),
                dlog.get('Detail'),
                dlog.get('User'),
                dlog.get('Device'),
                dlog.get('Type'),
                dlog.get('Level'),
            ))

        query_args = {
            "method": "log.stopFind",
            "params": {
                "token": dlog_token,
            },
            "object": object_id,
        }
        dh_data = self.send_call(query_args)
        if not dh_data.get('result'):
            log.failure('{} Failed'.format(query_args.get('method')))

        self.instance_service(method_name, stop=True)

        return

    def dh_test(self, msg):
        return
