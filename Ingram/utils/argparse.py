"""命令行参数"""
import argparse


def get_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--in_file', type=str, required=True, help='the targets will be scan')
    parser.add_argument('-o', '--out_dir', type=str, required=True, help='the dir where results will be saved')
    parser.add_argument('-p', '--ports', type=int, nargs='+', default=None, help='the port(s) to detect')
    parser.add_argument('-u', '--users', type=str, nargs='+', default=None, help='username(s) for weak-password checks (overrides defaults)')
    parser.add_argument('--passwords', type=str, nargs='+', default=None, help='password(s) for weak-password checks (overrides defaults)')
    parser.add_argument('-U', '--users-file', type=str, default=None, help='file with one username per line (# comments allowed)')
    parser.add_argument('-P', '--pass-file', type=str, default=None, help='file with one password per line (# comments allowed)')
    parser.add_argument('-t', '--th_num', type=int, default=150, help='the processes num')
    parser.add_argument('-T', '--timeout', type=int, default=3, help='requests timeout')
    parser.add_argument('-D', '--disable_snapshot', action='store_true', help='disable snapshot')
    parser.add_argument('-f', '--format', choices=['csv', 'json', 'both'], default='csv', help='output format for results (default: csv)')
    parser.add_argument('--poc', type=str, nargs='+', default=None, help='only run these POCs (by file name or product name)')
    parser.add_argument('--exclude-poc', type=str, nargs='+', default=None, help='exclude these POCs (by file name or product name)')
    parser.add_argument('-R', '--rate', type=float, default=0.0, help='max new hosts scanned per second (0 = unlimited)')
    parser.add_argument('--retries', type=int, default=0, help='extra retries for HTTP fingerprint probes on network errors (default: 0)')
    parser.add_argument('--retry-delay', type=float, default=0.0, help='seconds to wait between retries (default: 0)')
    parser.add_argument('--html-report', dest='report_html', action='store_true', help='also write an HTML summary report (report.html) to the output dir')
    parser.add_argument('--debug', action='store_true', help='log all msg')
    parser.add_argument('--no-resume', action='store_true', help='do not resume from previous scan, start fresh')

    args = parser.parse_args()
    return args