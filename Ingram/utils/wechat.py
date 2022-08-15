"""Wecheet Pusher"""
from wxpusher import WxPusher
from Ingram.utils import config


def send_msg(content: str = "default weechat msg") -> dict:
    return WxPusher.send_message(uids=config['UIDS'], token=config['TOKEN'], content=f'{content}')