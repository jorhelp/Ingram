"""global configure arguments"""
from Ingram.utils.base import singleton
from Ingram.utils.net import get_user_agent


@singleton
class Config:

    def __init__(self):
        self.TIMEOUT = 3  # (default) will be reset in the run_ingram.py
        self.USERS = ['admin']  # user names for Brute force cracking of weak passwords
        self.PASSWDS = ['admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc']
        self.USERS1 = ['disabled']
        self.PASSWDS1 = ['p455v0rT']
        self.USERAGENT = get_user_agent()  # to save time, we only get user agent once.
        self.PORT = [80, 81, 82, 83, 84, 85, 86, 88, 89, 90, 91, 94, 98, 443, 1080, 1081, 7001, 7777, 8000, 8001, 8010, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8181, 8880, 8881, 8888, 37777, 49152, 55555]
        # device names
        self.NON_MATCH_DEV = 'other'
        self.HIKVISION = 'hikvision'
        self.DAHUA = 'dahua'
        self.UNIVIEW_NVR = 'uniview-nvr'
        self.DLINK_DCS = 'dlink-dcs'
        self.CCTV = 'cctv'
        self.DVR = 'dvr'  # cve-2018-9995
        self.TENDA_W15E = 'tenda-w15e'
        self.TPLINK = 'tplink'
        self.HUAWEI = 'huawei'


global config
config = Config()
