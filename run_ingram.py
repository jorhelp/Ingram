#! /usr/bin/env python3
# coding: utf-8
# @Auth: Jor<jorhelp@qq.com>
# @Date: Wed Apr 20 00:17:30 HKT 2022
# @Desc: Ingram

import os

from Ingram.utils import config
from Ingram.utils import logo
from Ingram.utils import color
from Ingram.utils import get_parse
from Ingram.utils import logger, config_logger
from Ingram.utils import get_user_agent
from Ingram.core import Core


def assemble_config(args):
    config.set_val('IN', args.in_file)
    config.set_val('OUT', args.out_dir)
    config.set_val('TH', args.th_num)
    config.set_val('DEBUG', args.debug)
    config.set_val('TIMEOUT', args.time_out)
    config.set_val('PORT', args.port)

    config.set_val('MAXTRY', 2)  # since requests maybe failed, try N times
    config.set_val('LOGFILE', os.path.join(args.out_dir, 'log.txt'))  # log file
    config_logger(config['LOGFILE'], config['DEBUG'])  # logger configuration
    config.set_val('USERAGENT', get_user_agent())  # to save time, we only get user agent once.

    #--------- config below can be modified ---------
    config.set_val('USERS', ['admin'])  # user names for Brute force cracking of weak passwords
    config.set_val('PASSWDS', ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc'])
    config.set_val('WXUID', '')  # weechat uid used by wxpusher
    config.set_val('WXTOKEN', '')  # token used by wxpusher


if __name__ == '__main__':
    try:
        # logo
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")
        args = get_parse()  # args
        assemble_config(args)  # assemble global config vars
        core = Core()  # get ingram core
        core()  # run
        logger.info('Ingram done!')
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        logger.warning(e)
        print(color.red(f"error occurred, see the {config['OUT']}/log.txt for more information."))
        exit(0)
