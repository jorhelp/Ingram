"""detect the target info: fingerprint, port, etc..
TODO: add more device, such as router...
"""
import socket
import hashlib
import requests

from Ingram.utils import config
from Ingram.utils import logger


DEV_HASH = {
    '4ff53be6165e430af41d782e00207fda': config.DAHUA,
    '89b932fcc47cf4ca3faadb0cfdef89cf': config.HIKVISION,
    'f066b751b858f75ef46536f5b357972b': config.CCTV,
    '1536f25632f78fb03babedcb156d3f69': config.UNIVIEWNVR,
    'c30a692ad0d1324389485de06c96d9b8': 'uniview-dev',  # bugs
}
HEADERS = {'User-Agent': config.USERAGENT}
TIMEOUT = config.TIMEOUT


def device_detect(ip: str, port: str) -> str:
    """detect the device's fingerprint"""
    ip = f"{ip}:{port}"
    url_list = [
        f"http://{ip}/favicon.ico",  # hikvision, cctv, uniview-nvr
        f"http://{ip}/image/lgbg.jpg",  # Dahua
        f"http://{ip}/skin/default_1/images/logo.png",  # uniview-dev
        f"http://{ip}",  # dlink
    ]

    # these are need to be hashed
    for url in url_list[:-1]:
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False, headers=HEADERS)
            if r.status_code == 200:
                hash_val = hashlib.md5(r.content).hexdigest()
                if hash_val in DEV_HASH:
                    device = DEV_HASH[hash_val]
                    return device
        except Exception as e:
            logger.error(e)
    # not hash
    try:
        r = requests.get(url_list[-1], timeout=TIMEOUT, verify=False, headers=HEADERS)
        if 'WWW-Authenticate' in r.headers:
            if 'realm="DCS' in r.headers.get('WWW-Authenticate'):
                return 'dlink'
    except Exception as e:
        logger.error(e)

    return 'other'


def port_detect(ip: str, port: str) -> bool:
    """detect whether the port is open"""
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        res = s.connect_ex((ip, int(port)))
        if res == 0:
            logger.info(f"{ip} detect {port} is open")
            s.close()
            return True
    except Exception as e:
        s.close()
        logger.error(e)
    return False