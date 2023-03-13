"""vulnerablity database"""
from Ingram.VDB.weak_passwd import *
from Ingram.VDB.CVE_2021_36260 import cve_2021_36260
from Ingram.VDB.CVE_2017_7921 import cve_2017_7921
from Ingram.VDB.uniview_disclosure import disclosure
from Ingram.VDB.CVE_2020_25078 import cve_2020_25078
from Ingram.VDB.CVE_2021_33044 import cve_2021_33044
from Ingram.VDB.CVE_2021_33045 import cve_2021_33045
from Ingram.VDB.CVE_2017_14514 import cve_2017_14514
from Ingram.VDB.CVE_2018_9995 import cve_2018_9995
from Ingram.utils import config


def get_vul(dev: str) -> list:
    """return a list of modules according to the device type"""
    if dev == config.HIKVISION:
        return [hikvision_weak, cve_2021_36260, cve_2017_7921]
    elif dev == config.DAHUA:
        return [dahua_disabled, dahua_weak, cve_2021_33044, cve_2021_33045]
    elif dev == config.UNIVIEW_NVR:
        return [disclosure, ]
    elif dev == config.DLINK_DCS:
        return [cve_2020_25078, ]
    elif dev == config.CCTV:
        return [cctv_weak, ]
    elif dev == config.TENDA_W15E:
        return [cve_2017_14514, ]
    elif dev == config.DVR:
        return [cve_2018_9995, ]
    else:
        return []