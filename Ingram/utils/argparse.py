"""args"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('-p', '--port', type=int, nargs='+', default=80, help='the port(s) to detect')
    parser.add_argument('-t', '--th_num', type=int, default=150, help='the processes num')
    parser.add_argument('-T', '--time_out', type=int, default=2, help='requests timeout')
    parser.add_argument('--debug', action='store_true', help='log all msg')

    args = parser.parse_args()
    return args