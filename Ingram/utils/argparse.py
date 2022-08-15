"""args"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('--debug', action='store_true', help='log all msg')

    parser.add_argument('-p', '--port', type=int, nargs='+', default=80, help='the port(s) to detect')
    parser.add_argument('-t', '--th_num', type=int, default=64, help='the processes num')
    parser.add_argument('-N', '--nosnap', action='store_true', help='do not capture the snapshot')
    parser.add_argument('--time_out', type=int, default=3, help='requests timeout')

    args = parser.parse_args()
    return args