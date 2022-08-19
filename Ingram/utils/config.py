"""global configure arguments"""
from Ingram.utils.base import singleton
from Ingram.utils.net import get_user_agent


@singleton
class Config:

    def __init__(self):
        self.MAXTRY = 2  # since requests maybe failed, try N times
        self.TIMEOUT = 3  # (default) will be reset in the run_ingram.py
        self.USERS = ['admin']  # user names for Brute force cracking of weak passwords
        self.PASSWDS = ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc']
        self.USERAGENT = get_user_agent()  # to save time, we only get user agent once.

        # device names
        self.HIKVISION = 'hikvision'
        self.DAHUA = 'dahua'
        self.UNIVIEWNVR = 'uniview-nvr'
        self.DLINK = 'dlink'
        self.CCTV = 'cctv'


global config
config = Config()