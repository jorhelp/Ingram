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
    parser.add_argument('--in_file', type=str, required=True, help='the input file')
    parser.add_argument('--out_file', type=str, default='results', help='the dir where results saved')
    parser.add_argument('--send_msg', action='store_true', help='send finished msg to you (by wechat or email)')

    parser.add_argument('--all', action='store_true')
    parser.add_argument('--masscan', action='store_true')
    parser.add_argument('--hik_weak', action='store_true')
    parser.add_argument('--dahua_weak', action='store_true')
    parser.add_argument('--cctv_weak', action='store_true')
    parser.add_argument('--hb_weak', action='store_true')
    parser.add_argument('--cve_2021_36260', action='store_true')
    parser.add_argument('--cve_2021_33044', action='store_true')
    parser.add_argument('--cve_2017_7921', action='store_true')
    parser.add_argument('--cve_2020_25078', action='store_true')

    parser.add_argument('--port', type=int, default=80, help='masscan')
    parser.add_argument('--rate', type=int, default=5000, help='masscan')
    parser.add_argument('--th_num', type=int, default=32, help='hikvision')
    parser.add_argument('--users', type=str, nargs='+', default=['admin'], help='weak pass users')
    parser.add_argument('--passwords', type=str, nargs='+', default=['admin12345', 'asdf1234', '12345'], help='weak pass passwords')

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
        scn = scanner.MasScaner(args.in_file, args.out_file)
        scn(args)
    else:
        scn = scanner.CameraScanner(args.in_file, args.out_file)
        scn(args)

    # finished
    if args.send_msg:
        send_msg(f"{scn.scanner_name} finished!")


if __name__ == '__main__':
    args = get_parser()
    run(args)
