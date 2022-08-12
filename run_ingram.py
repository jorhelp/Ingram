#! /usr/bin/env -S python3 -Bu
# coding: utf-8
# @Auth: Jor<jorhelp@qq.com>
# @Date: Wed Apr 20 00:17:30 HKT 2022
# @Desc: Ingram

import argparse
import warnings

from Ingram.utils.logo import logo
from Ingram.utils.color import color
from Ingram.utils.config import config
from Ingram.utils.time import get_current_time
from Ingram.utils.log import logger


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('--debug', action='store_false', help='log all msg')

    parser.add_argument('--th_num', type=int, default=80, help='the processes num')
    parser.add_argument('--nosnap', action='store_false', help='do not capture the snapshot')
    parser.add_argument('--time_out', type=int, default=2, help='requests timeout')

    # masscan
    parser.add_argument('--masscan', action='store_true', help='run massscan sanner')
    parser.add_argument('--port', type=str, default=80, help='same as masscan port')
    parser.add_argument('--rate', type=int, default=5000, help='same as masscan rate')

    args = parser.parse_args()
    return args


def run(args):
    config.set_val('IN', args.in_file)
    config.set_val('OUT', args.out_dir)
    config.set_val('THNUM', args.th_num)
    config.set_val('NOSNAP', args.nosnap)
    config.set_val('DEBUG', args.debug)
    config.set_val('TIMEOUT', args.time_out)

    config.set_val('MAX_TRIES', 2)  # since requests maybe failed, try N times
    config.set_val('USERS', ['admin'])  # user names for Brute force cracking of weak passwords
    config.set_val('PASSWDS', ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc'])
    config.set_val('WXUID', '')  # weechat uid used by wxpusher
    config.set_val('WXTOKEN', '')  # token used by wxpusher


if __name__ == '__main__':
    warnings.filterwarnings("ignore")
    # logo
    for icon, font in zip(*logo):
        print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")
    # args = get_parser()
    # run(args)

    # logger.info(config['USERS'])
    # logger.warning(config['THNUM'])
    # logger.error(config['IN'])
    # logger.debug(config['OUT'])
