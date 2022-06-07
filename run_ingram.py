#! /usr/bin/env -S python3 -Bu
# coding: utf-8
# @Auth: Jor<jorhelp@qq.com>
# @Date: Wed Apr 20 00:17:30 HKT 2022
# @Desc: Ingram

import argparse
import warnings
warnings.filterwarnings("ignore")

from scan import scanner
from utils.base import printf
from utils.wechat import send_msg


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('--out_path', type=str, default='results', help='the path where results saved')
    parser.add_argument('--send_msg', action='store_true', help='send finished msg to you (by wechat or email)')

    parser.add_argument('--all', action='store_true', help='scan all the modules of [hik_weak, dahua_weak, cve_...]')
    parser.add_argument('--hik_weak', action='store_true')
    parser.add_argument('--dahua_weak', action='store_true')
    parser.add_argument('--cctv_weak', action='store_true')
    parser.add_argument('--hb_weak', action='store_true')
    parser.add_argument('--cve_2021_36260', action='store_true')
    parser.add_argument('--cve_2021_33044', action='store_true')
    parser.add_argument('--cve_2017_7921', action='store_true')
    parser.add_argument('--cve_2020_25078', action='store_true')
    parser.add_argument('--th_num', type=int, default=80, help='the processes num')

    parser.add_argument('--masscan', action='store_true', help='run massscan sanner')
    parser.add_argument('--port', type=str, default=80, help='same as masscan port')
    parser.add_argument('--rate', type=int, default=5000, help='same as masscan rate')

    args = parser.parse_args()
    return args


def run(args):
    # readme
    flag, count = False, 0
    colors = ['red', 'cyan', 'green', 'blue', 'pink', 'white']
    with open('README.md', 'r') as f:
        for line in f:
            if line.startswith('#'): break
            if line.startswith('```'):
                if flag:
                    print()
                    count += 1
                flag = not flag
            elif flag: printf(line.rstrip(), color=colors[count % len(colors)], bold=True)

    # scan
    if args.masscan:
        scn = scanner.MasScaner(args)
        scn()
    else:
        scn = scanner.CameraScanner(args)
        scn()

    # finished
    if args.send_msg:
        send_msg(f"{scn.scanner_name} finished!")


if __name__ == '__main__':
    args = get_parser()
    run(args)
