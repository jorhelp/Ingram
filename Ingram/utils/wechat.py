"""Wecheet Pusher"""
from wxpusher import WxPusher
from Ingram.utils.config import config


def wx_send(content: str = "default weechat msg") -> dict:
    return WxPusher.send_message(uids=[config.UIDS, ], token=config.TOKEN, content=f'{content}')