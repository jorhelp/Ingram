"""Integrazione: --html-report scrive report.html tramite Core.report().
Core/Data sono singleton -> girare in un subprocess pulito."""
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    tmp = tempfile.mkdtemp()
    in_file = os.path.join(tmp, 'input')
    out_dir = os.path.join(tmp, 'out')
    os.makedirs(os.path.join(out_dir, 'snapshots'))
    with open(in_file, 'w') as f:
        f.write('1.2.3.4\n')

    # risultato pregresso su disco, così report() ha qualcosa da riportare
    with open(os.path.join(out_dir, 'results.csv'), 'w') as f:
        f.write('1.2.3.4,80,hikvision,admin,admin,cve-2021-36260\n')

    from Ingram import get_config
    from Ingram.core import Core
    args = argparse.Namespace(
        in_file=in_file, out_dir=out_dir, ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=5, timeout=1,
        disable_snapshot=True, format='csv', poc=None, exclude_poc=None,
        rate=0.0, retries=0, retry_delay=0.0, report_html=True,
        debug=False, no_resume=True)
    config = get_config(args)

    core = Core(config)
    core.report()

    report_path = os.path.join(out_dir, 'report.html')
    assert os.path.isfile(report_path), 'report.html non generato'
    body = open(report_path, encoding='utf-8').read()
    assert body.startswith('<!DOCTYPE html>')
    assert 'cve-2021-36260' in body
    assert 'HIGH' in body                    # severità arricchita dal POC reale
    assert '1.2.3.4' in body
    print('html report file OK:', report_path)


if __name__ == '__main__':
    main()
