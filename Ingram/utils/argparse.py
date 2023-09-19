"""命令行参数"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=None, help='the port(s) to detect')
    parser.add_argument('-t', '--th_num', type=int, default=150, help='the processes num')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='requests timeout')
    parser.add_argument('-D', '--disable_snapshot', action='store_true', help='disable snapshot')
    parser.add_argument('--debug', action='store_true', help='log all msg')

    args = parser.parse_args()
    return args