"""vulnerablity database"""
from Ingram.module.weak_passwd import *
from Ingram.module.CVE_2021_36260 import cve_2021_36260
from Ingram.module.CVE_2017_7921 import cve_2017_7921
from Ingram.module.uniview_disclosure import disclosure
from Ingram.module.CVE_2020_25078 import cve_2020_25078
from Ingram.module.CVE_2021_33044 import cve_2021_33044
from Ingram.module.CVE_2021_33045 import cve_2021_33045


def get_module(dev: str) -> list:
    """return a list of modules according to the device type"""
    if dev == 'hikvision':
        return [hikvision_weak, cve_2021_36260, cve_2017_7921]
    elif dev == 'dahua':
        return [dahua_weak, cve_2021_33044, cve_2021_33045]
    elif dev == 'uniview-nvr':
        return [disclosure, ]
    elif dev == 'dlink':
        return [cve_2020_25078, ]
    elif dev == 'cctv':
        return [cctv_weak, ]
    else:
        return None