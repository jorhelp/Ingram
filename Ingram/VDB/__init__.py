"""vulnerablity database"""
from Ingram.VDB.weak_passwd import *
from Ingram.VDB.CVE_2021_36260 import cve_2021_36260
from Ingram.VDB.CVE_2017_7921 import cve_2017_7921
from Ingram.VDB.uniview_disclosure import disclosure
from Ingram.VDB.CVE_2020_25078 import cve_2020_25078
from Ingram.VDB.CVE_2021_33044 import cve_2021_33044
from Ingram.VDB.CVE_2021_33045 import cve_2021_33045
from Ingram.utils import config


def get_vul(dev: str) -> list:
    """return a list of modules according to the device type"""
    if dev == config.HIKVISION:
        return [hikvision_weak, cve_2021_36260, cve_2017_7921]
    elif dev == config.DAHUA:
        return [dahua_weak, cve_2021_33044, cve_2021_33045]
    elif dev == config.UNIVIEWNVR:
        return [disclosure, ]
    elif dev == config.DLINK:
        return [cve_2020_25078, ]
    elif dev == config.CCTV:
        return [cctv_weak, ]
    else:
        return None