"""Wecheet Pusher"""
import os
import sys

from wxpusher import WxPusher

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from utils.config import UIDS, TOKEN


def send_msg(content: str = "default content") -> dict:
    return WxPusher.send_message(uids=UIDS, token=TOKEN, content=f'{content}')


if __name__ == '__main__':
    # just for testing
    print(send_msg())
