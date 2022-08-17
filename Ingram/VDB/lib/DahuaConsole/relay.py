import requests
from requests import packages
from requests.packages import urllib3
from requests.packages.urllib3 import exceptions
from pathlib import Path

from utils import *


def custom_checksec(host, port, message):
    """ Some embedded devices with 'psh' will hang after checksec() """
    cache_dir = ''.join(tempfile.gettempdir() + '/pwntools-ssh-cache')
    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    fpath = ''.join(cache_dir + '/{}-{}'.format(host, port))
    with open(fpath, 'w+') as f:
        f.write(message)


def init_relay(relay=None, rhost=None, rport=None, discover=False):
    """ Relay via SSH """
    dh_remote = None
    # import paramiko
    # paramiko ssh debugging
    # logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    # logging.basicConfig(stream=sys.stdout)

    try:
        proto = relay[0:relay.index('://')]
        tmp = relay[len(proto)+3:].split('@')
        relay_username = tmp[0].split(':')[0]
        relay_password = tmp[0].split(':')[1]
        relay_rhost = tmp[1].split(':')[0]
        relay_rport = tmp[1].split(':')[1]

        """ Check if RPORT is valid """
        if not check_port(relay_rport):
            log.failure("Invalid relay port - Choose between 1 and 65535")
            return False

        """ Check if RHOST is valid IP or FQDN, get IP back """
        if not check_host(relay_rhost):
            log.failure("Invalid relay host")
            return False

    except (ValueError, IndexError):
        log.failure('relay usage: <proto>://<user>:<password>@<host|fqdn>:<port>')
        return False

    if proto == 'ssh':
        message = '(null)'
        custom_checksec(host=relay_rhost, port=relay_rport, message=message)
        try:
            dh_relay = ssh(
                user=relay_username,
                password=relay_password,
                host=relay_rhost,
                port=int(relay_rport),
                timeout=60,
                cache=False
            )
            # return relay
        except Exception as e:
            print('[init_relay] ssh: {}'.format(repr(e)))
            return False

        if not discover:
            try:
                dh_remote = dh_relay.connect_remote(rhost, rport)
            except AttributeError:
                dh_relay.close()
                return False
            except Exception as e:
                print('[init_relay] remote: ', repr(e))
                dh_relay.close()
                return False

            """
            print(relay.transport.remote_version)
            print(relay.transport.local_version)
            print(relay.transport.remote_mac)
            print(relay.transport.local_mac)
            print(relay.transport.remote_cipher)
            print(relay.transport.get_security_options())
            """
        return {
            "dh_relay": dh_relay,
            "dh_remote": dh_remote
            }

    else:
        log.failure('"{}" relay proto not implemented'.format(proto))
        return False


class DahuaHttp(object):
    def __del__(self):
        log.info('DahuaHttp DELETE')

    """ Dahua http """
    # TODO
    # Get HTTP/HTTPS working with SSH relay
    def __init__(self, rhost, rport, proto, timeout=60):
        super(DahuaHttp, self).__init__()

        self.rhost = rhost
        self.rport = rport
        self.proto = proto
        self.timeout = timeout

        self.remote = None
        self.uri = None
        self.stream = None

        """ Most devices will use self-signed certificates, suppress any warnings """
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        self.remote = requests.Session()

        """Used with _debug"""
        self.headers = self.remote.headers
        self.cookies = self.remote.cookies

        self._init_uri()

        import random as random_agent
        random_agent.seed(1)
        self.remote.headers.update({
            'User-Agent': useragents.random(),
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Host': '{}:{}'.format(self.rhost, self.rport),
        })
        # TODO
        """To use '--relay' option"""
        """
        self.remote.proxies.update({
            # 'http': 'http://127.0.0.1:8080',
        })
        """

    def send(self, url=None, query_args=None, login=False, timeout=5):

        """JSON API communication"""
        if query_args:
            if query_args.get('params') is not None and not len(query_args.get('params')):
                query_args.update({'params': None})

        """This weird code will try automatically switch between http/https
        and update Host
        """
        try:
            if url and not query_args:
                return self.get(url, timeout)
            else:
                dh_data = self.post(self._get_url(login, url), query_args, timeout)
        except requests.exceptions.ConnectionError:
            self.proto = 'https' if self.proto == 'http' else 'https'
            self._init_uri()
            try:
                if url and not query_args:
                    return self.get(url, timeout)
                else:
                    dh_data = self.post(self._get_url(login, url), query_args, timeout)
            except requests.exceptions.ConnectionError as e:
                if login:
                    return self._error(dh_error=e)
                return None
        except requests.exceptions.RequestException as e:
            if login:
                return self._error(dh_error=e)
            return None
        except KeyboardInterrupt:
            return None

        """302 when requesting http on https enabled device"""
        if dh_data.status_code == 302:
            redirect = dh_data.headers.get('Location')
            self.uri = redirect[:redirect.rfind('/')]
            self._update_host()
            if url and not query_args:
                return self.get(url, timeout)
            else:
                dh_data = self.post(self._get_url(login, url), query_args, timeout)

        """Catch non dahua hosts"""
        if not dh_data.status_code == 200:
            return self._error(dh_error=dh_data.text, code=dh_data.status_code)

        """JSON API communication"""
        dh_json = dh_data.json()

        """Set SessionID Cookie during login"""
        if login and self.remote.cookies.get('DWebClientSessionID') is None:
            self.remote.cookies.set('username', query_args.get('params').get('userName'))
            self.remote.cookies.set('DWebClientSessionID', str(dh_json.get('session')))

        return dh_data

    @staticmethod
    def _get_url(login, url):
        if login:
            return '/RPC2_Login'
        elif url:
            """GET or other POST JSON API communication"""
            return url
        """Default JSON API communication"""
        return '/RPC2'

    def _update_host(self):
        if not self.remote.headers.get('Host') == self.uri[self.uri.rfind('://') + 3:]:
            self.remote.headers.update({
                'Host': self.uri[self.uri.rfind('://') + 3:],
            })

    def _init_uri(self):
        self.uri = '{proto}://{rhost}:{rport}'.format(proto=self.proto, rhost=self.rhost, rport=str(self.rport))

    @staticmethod
    def _error(dh_error=None, code=500):
        """Keep 'login' happy and give some info back in case of failure"""
        return json.dumps({'result': False, 'error': {'code': code, 'message': str(dh_error)}})

    def options(self):
        timeout = 10
        req = requests.Request('OPTIONS', 'rtsp://{host}:{port}?proto=Onvif RTSP/1.1\r\nCSeq: 1\r\n\r\n'.format(
            host='192.168.5.27', port=80))
        print(req.prepare())
        print(req.url)
        dh_data = self.remote.send(req.url, verify=False, allow_redirects=False, timeout=timeout)
        print(dh_data)

    def post(self, url, query_args, timeout):
        """JSON API Communication"""
        return self.remote.post(self.uri + url, json=query_args, verify=False, allow_redirects=False, timeout=timeout)

    def get(self, url, timeout):
        """Non JSON Communication"""
        return self.remote.get(self.uri + url, verify=False, allow_redirects=False, timeout=timeout)

    def open_stream(self, session_id):
        """Open stream session for events and other 'client.Notify'"""
        self.stream = self.remote.get(
            '{}/SubscribeNotify.cgi?sessionId={}'.format(self.uri, session_id),
            verify=False, allow_redirects=False, stream=True
        )

    def recv_stream(self):
        """Return events and other 'client.Notify'"""
        return fix_json(self.stream.raw.readline().decode('utf-8'))

    @staticmethod
    def can_recv():
        """We do not expect unexpected data
        the 'stream' above will handle that"""
        return False

    @staticmethod
    def connected():
        # TODO: Assume connected, should find a way to check
        return True

    def close(self):
        # TODO: Not really sure if this way
        self.remote.close()
        return True
