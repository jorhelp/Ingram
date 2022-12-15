"""detect the target info: fingerprint, port, etc..
TODO: add more device, such as router...
"""
import re
import socket
import hashlib
import requests

from Ingram.utils import config
from Ingram.utils import logger


DEV_HASH = {
    'bd9e17c46bbbc18af2a2bd718dddad0e': config.DAHUA,
    '605f51b413980667766a9aff2e53b9ed': config.DAHUA,
    'b39f249362a2e4ab62be4ddbc9125f53': config.DAHUA,
    '4ff53be6165e430af41d782e00207fda': config.DAHUA,
    '89b932fcc47cf4ca3faadb0cfdef89cf': config.HIKVISION,
    'f066b751b858f75ef46536f5b357972b': config.CCTV,
    '1536f25632f78fb03babedcb156d3f69': config.UNIVIEW_NVR,
    'c30a692ad0d1324389485de06c96d9b8': 'uniview-dev',  # bugs
}
HEADERS = {'Connection': 'close', 'User-Agent': config.USERAGENT}
TIMEOUT = config.TIMEOUT


def device_detect(ip: str, port: str) -> str:
    """detect the device's fingerprint"""
    ip = f"{ip}:{port}"
    url_list = [
        f"http://{ip}/favicon.ico",  # hikvision, cctv, uniview-nvr, dahua
        f"http://{ip}/image/lgbg.jpg",  # Dahua
        f"http://{ip}/skin/default_1/images/logo.png",  # uniview-dev
        f"http://{ip}",  # dlink
        f"http://{ip}/login.rsp"  # dvr
    ]

    # these are need to be hashed
    for url in url_list[:3]:
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
        r = requests.get(url_list[-2], timeout=TIMEOUT, verify=False, headers=HEADERS)
        title = re.findall(r'<title>(.*)</title>', r.text)
        if title:
            title = title[0].lower()
            if title == 'Tenda | login':
                return config.TENDA_W15E
            if 'dvr' in title or 'xvr' in title or 'nvr' in title or 'hvr' in title:
                return config.DVR
        if 'WWW-Authenticate' in r.headers:
            if 'realm="DCS' in r.headers.get('WWW-Authenticate'):
                return config.DLINK_DCS
    except Exception as e:
        logger.error(e)

    # dvr
    try:
        r = requests.get(url_list[-1], timeout=TIMEOUT, verify=False, headers=HEADERS)
        if r.status_code == 200:
            return config.DVR
    except Exception as e:
        logger.error(e)

    return config.NON_MATCH_DEV


def port_detect(ip: str, port: str) -> bool:
    """detect whether the port is open"""
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    s.settimeout(1)
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
