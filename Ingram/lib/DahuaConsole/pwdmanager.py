from utils import *
from dahua_logon_modes import dahua_logon, dahua_gen1_hash, dahua_gen2_md5_hash, dahua_onvif_sha1_hash


class PwdManager(object):
    """ Dahua HASH / pwd Manager functions """
    def __init__(self):
        super(PwdManager, self).__init__()

    def dvrip(self, rhost=None, username=None, password=None, proto=None, query_args=None, login=None):

        saved_host = None

        if not password:
            if proto == '3des':
                login.failure(color('3DES: You need to use --auth <username>:<password>', RED))
                return False

            saved_host = self.get_host(rhost)
            if not saved_host:
                login.failure(color('You need to use --auth <username>:<password> [--save]', RED))
                return False

        if proto == '3des':
            params = dahua_logon(
                logon=proto, username=username, password=password)
            return params

        elif proto == 'dvrip':

            if not query_args.get('random'):
                login.failure(color('Realm [random]', RED))
                return None

            if not password:
                saved_host = self.get_host(rhost, query_args.get('realm'))
                if not saved_host:
                    login.failure(color('You need to use --auth <username>:<password> [--save]', RED))
                    return None
                username = saved_host.get('username')

            params = dahua_logon(
                logon=proto, query_args=query_args, username=username, password=password, saved_host=saved_host)
            return params
        else:
            login.failure(color('Invalid "proto"!', RED))
            return None

    def dhip(self, rhost=None, query_args=None, username=None, password=None, login=None, logon=None, force=False):

        saved_host = None

        if not password:
            saved_host = self.get_host(rhost)
            if not saved_host:
                login.failure(color('You need to use --auth <username>:<password> [--save]', RED))
                return False
            username = saved_host.get('username')
            password = None

        if query_args.get('method') == 'global.login':

            if logon == 'wsse':
                if not force:
                    log.warning(f'[{logon}] Can only be used once per boot!')
                    log.warning("If you still want to try, run this script with --force")
                    return False

            params = dahua_logon(init=True, username=username, logon=logon)
            return params

        elif query_args.get('error').get('code') in [268632079, 401]:  # DHIP REALM

            if not password:
                # We just checking RandSalt from REALM here
                dh_data = self.get_host(rhost, query_args.get('params').get('realm'))
                if not dh_data:
                    login.failure(color('You need to use --auth <username>:<password> [--save]', RED))
                    return False
                """
                if not (encryption == 'Default' or encryption == 'OldDigest'):
                    login.failure(
                        color('Encryption: "{}", You need to use --auth <username>:<password>'.format(encryption), RED))
                    return False
                """

            params = dahua_logon(
                logon=logon, query_args=query_args, username=username, password=password, saved_host=saved_host)
            return params

    @staticmethod
    def read_hosts():

        try:
            with open('dhConsole.json') as fd:
                return json.load(fd)
        except IOError as e:
            log.failure(color('[read_hosts] {}'.format(str(e)), RED))
            return None

    @staticmethod
    def write_hosts(dh_data):

        try:
            with open('dhConsole.json', 'w') as fd:
                json.dump(dh_data, fd)
                os.chmod('dhConsole.json', stat.S_IRUSR | stat.S_IWUSR)
                log.success(color('Host saved successfully', GREEN))
                return True
        except Exception as e:
            log.failure(color('[write_hosts] {}'.format(repr(e)), RED))
            return None

    def get_relay(self, rhost=None):

        dh_data = self.find_host(rhost)
        if not dh_data:
            return False

        return dh_data.get('relay')

    def save_host(self, rhost, rport, proto, username, password, dh_realm, relay, events, logon):

        # TODO: save some logon

        host = None

        dh_data = self.read_hosts()
        if not dh_data:
            dh_data = []

        if not self.find_host(rhost):
            log.info(f'Adding new host "{rhost}"')
            dh_data.append({
                "host": rhost,
                "port": rport,
                "proto": proto,
                "username": username,
                "password": {
                    "gen1": dahua_gen1_hash(password),
                    "gen2": dahua_gen2_md5_hash(
                        dh_realm=dh_realm, username=username, password=password, return_hash=True),
                    "RandSalt": dh_realm.split()[2],
                    "onvif": dahua_onvif_sha1_hash(password=password) if logon == 'onvif:onvif' else None
                },
                "events": events,
                "relay": relay,
                "logon": logon
            })
        else:
            log.info(f'Updating host "{rhost}"')
            for host in range(0, len(dh_data)):
                if rhost == dh_data[host].get('host'):
                    break

            dh_data[host].update({
                "host": rhost,
                "port": rport,
                "proto": proto,
                "username": dh_data[host].get('username') if not username else username,
                "password": {
                    "gen1": dh_data[host].get('password').get('gen1') if not password else dahua_gen1_hash(password),
                    "gen2": dh_data[host].get('password').get('gen2') if not password else dahua_gen2_md5_hash(
                        dh_realm=dh_realm, username=username, password=password, return_hash=True),
                    "RandSalt": dh_realm.split()[2],
                    "onvif": dahua_onvif_sha1_hash(password=password) if logon == 'onvif:onvif' else None
                },
                "events": events,
                "relay": relay,
                "logon": logon
            })

        if not self.write_hosts(dh_data):
            return False

        return True

    def get_host(self, host=None, dh_realm=None):

        dh_data = self.find_host(host)

        if dh_data is None:
            log.failure(f'Host "{host}" do not exist')
            return None
        elif not dh_data:
            return False

        if dh_realm:
            rand_salt = dh_realm.split()[2]
            if not dh_data.get('password').get('RandSalt') == rand_salt:
                log.failure(color('RandSalt differs, current hash does not work anymore!', LRED))
                return False

        return dh_data

    def find_host(self, host=None):

        dh_data = self.read_hosts()
        if not dh_data:
            return False
        if not host:
            return dh_data

        for hosts in range(0, len(dh_data)):
            if host == dh_data[hosts].get('host'):
                return dh_data[hosts]
        return None
