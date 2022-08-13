"""get the target fingerprint"""
import hashlib
import requests
import aiohttp

from Ingram.utils import config
from Ingram.utils import logger


DEV_HASH = {
    '4ff53be6165e430af41d782e00207fda': 'dahua',
    '89b932fcc47cf4ca3faadb0cfdef89cf': 'hikvision',
    'f066b751b858f75ef46536f5b357972b': 'cctv',
    '1536f25632f78fb03babedcb156d3f69': 'uniview-nvr',
    'c30a692ad0d1324389485de06c96d9b8': 'uniview-dev',
}


async def check_device(ip: str) -> list:
    """Check whether the ip is a web camera"""
    url_list = [
        f"http://{ip}/favicon.ico",  # hikvision, cctv, uniview-nvr
        f"http://{ip}/image/lgbg.jpg",  # Dahua
        f"http://{ip}/skin/default_1/images/logo.png",  # uniview-dev
        f"http://{ip}",  # dlink
    ]
    timeout = config['TIMEOUT']

    # these are need to be hashed
    for url in url_list[:-1]:
        try:
            with aiohttp.ClientSession() as session:
                r = session.get(url, timeout=timeout, verify=False)
            # r = requests.get(url, timeout=config['TIMEOUT'], verify=False)
                if r.status_code == 200:
                    hash_val = hashlib.md5(r.content).hexdigest()
                    if hash_val in DEV_HASH:
                        device = DEV_HASH[hash_val]
                        logger.info(f"{ip} is {device}")
                        return device
        except Exception as e:
            logger.error(e)
    # not hash
    try:
        r = requests.get(url_list[-1], timeout=config['TIMEOUT'], verify=False)
        if 'realm="DCS' in str(r.headers):
            logger.info(f"{ip} is dlink")
            return 'dlink'
    except Exception as e:
        logger.error(e)

    return 'other'