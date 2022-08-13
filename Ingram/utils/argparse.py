"""args"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('--debug', action='store_true', help='log all msg')

    parser.add_argument('-t', '--th_num', type=int, default=80, help='the processes num')
    parser.add_argument('-N', '--nosnap', action='store_false', help='do not capture the snapshot')
    parser.add_argument('--time_out', type=int, default=3, help='requests timeout')

    # masscan
    parser.add_argument('--masscan', action='store_true', help='run massscan sanner')
    parser.add_argument('--port', type=str, default=80, help='same as masscan port')
    parser.add_argument('--rate', type=int, default=5000, help='same as masscan rate')

    args = parser.parse_args()
    return args