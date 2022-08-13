#! /usr/bin/env -S python3 -Bu
# coding: utf-8
# @Auth: Jor<jorhelp@qq.com>
# @Date: Wed Apr 20 00:17:30 HKT 2022
# @Desc: Ingram

import os
import warnings

from Ingram.utils import config
from Ingram.utils import logo
from Ingram.utils import color
from Ingram.utils import get_parse
from Ingram.utils import config_logger
from Ingram.utils import get_user_agent
from Ingram.core import run


def assemble_config(args):
    config.set_val('IN', args.in_file)
    config.set_val('OUT', args.out_dir)
    config.set_val('THNUM', args.th_num)
    config.set_val('NOSNAP', args.nosnap)
    config.set_val('DEBUG', args.debug)
    config.set_val('TIMEOUT', args.time_out)

    config.set_val('MAXTRIES', 2)  # since requests maybe failed, try N times
    config.set_val('LOGFILE', os.path.join(args.out_dir, 'log.txt'))  # log file
    config_logger(config['LOGFILE'], config['DEBUG'])  # logger configuration
    config.set_val('USERAGENT', get_user_agent())  # to save time, we only get user agent once.

    #--------- config below can be modified ---------
    config.set_val('USERS', ['admin'])  # user names for Brute force cracking of weak passwords
    config.set_val('PASSWDS', ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc'])
    config.set_val('WXUID', '')  # weechat uid used by wxpusher
    config.set_val('WXTOKEN', '')  # token used by wxpusher


if __name__ == '__main__':
    warnings.filterwarnings("ignore")

    # logo
    for icon, font in zip(*logo):
        print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")

    args = get_parse()  # args
    assemble_config(args)  # assemble global config vars

    run()