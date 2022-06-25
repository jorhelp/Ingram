"""display the camera in rtsp"""
import argparse

import cv2
import rtsp


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, required=True, help='the target that to be displayed')
    parser.add_argument('--user', type=str, required=True, help='user name')
    parser.add_argument('--passwd', type=str, required=True, help='password')
    parser.add_argument('--x', type=int, default=0, required=False, help='window location x')
    parser.add_argument('--y', type=int, default=0, required=False, help='window location y')
    parser.add_argument('--height', type=int, default=640, required=False, help='window height')

    args = parser.parse_args()
    return args


def show(args):
    with rtsp.Client(rtsp_server_uri=f"rtsp://{args.user}:{args.passwd}@{args.ip}:554", verbose=False) as client:
        win_name = f"{args.ip}({args.user}:{args.passwd})"
        cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)
        cv2.moveWindow(win_name, args.x, args.y)  # window location

        while (client.isOpened()):
            img = client.read(raw=True)  # camera img

            # resize
            scale = args.height / img.shape[0]
            img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

            cv2.imshow(win_name, img)
            if cv2.waitKey(30) == ord('q'): # wait 30 ms for 'q' input
                break
        cv2.waitKey(1)
        cv2.destroyAllWindows()
        cv2.waitKey(1)


if __name__ == '__main__':
    args = get_parser()
    show(args)
