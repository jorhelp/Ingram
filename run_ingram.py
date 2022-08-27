#! /usr/bin/env python3
# coding: utf-8
# @Auth: Jor<jorhelp@qq.com>
# @Date: Wed Apr 20 00:17:30 HKT 2022
# @Desc: Ingram

from gevent import monkey; monkey.patch_all(thread=False)
import os

from Ingram.utils import config
from Ingram.utils import logo
from Ingram.utils import color
from Ingram.utils import wx_send
from Ingram.utils import get_parse
from Ingram.utils import logger, config_logger
from Ingram.core import Core


def assemble_config(args):
    #------- user defined configuration ------
    config.WXUID = ''  # weechat uid
    config.WXTOKEN = ''  # weechat token
    #----------------- end -------------------

    config.IN = args.in_file
    config.OUT = args.out_dir
    config.TH = args.th_num
    config.DEBUG = args.debug
    config.TIMEOUT = args.time_out
    config.LOGFILE = os.path.join(config.OUT, 'log.txt')  # log file
    if args.port:
        config.PORT = args.port

    if not os.path.isfile(config.IN):
        print(f"{color.red('the input file')} {color.yellow(config.IN)} {color.red('does not exists!')}")
        exit(0)

    if os.path.isfile(config.OUT):
        print(f"{color.yellow(config.OUT)} {color.red('is a file, please use another name')}")
        exit(0)

    # mk out dir, and the config_logger will be success
    if not os.path.isdir(config.OUT):
        os.mkdir(config.OUT)
    config_logger(config.LOGFILE, config.DEBUG)  # logger configuration


if __name__ == '__main__':
    try:
        # logo
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")
        assemble_config(get_parse())  # assemble global config vars
        core = Core()  # get ingram core
        core()  # run
        logger.info('Ingram done!')
        if config.WXUID and config.WXTOKEN:
            try:
                wx_send('Ingram done!')
            except Exception as e:
                logger.error(e)
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        logger.warning(e)
        print(f"{color.red('error occurred, see the')} {color.yellow(config.LOGFILE)} "
              f"{color.red('for more information.')}")
        exit(0)
