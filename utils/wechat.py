"""Wecheet Pusher"""
from typing import Dict
from wxpusher import WxPusher


def send_msg(content: str = "default content") -> Dict:
    return WxPusher.send_message(uids=[''],
                                 token='',
                                 content=f'{content}')


if __name__ == '__main__':
    # just for testing
    print(send_msg())
