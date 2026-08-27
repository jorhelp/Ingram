"""Integrazione: scrittura file di risultato per formato csv/json/both.
Data e' singleton -> ogni formato gira in un subprocess pulito."""
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# valore contenente una virgola: dimostra che il JSON non si rompe come il CSV
VULN = ['1.2.3.4', '80', 'dahua', 'admin', 'pa,ss', 'dahua-weak-password']
NOTV = ['5.6.7.8', '81', 'hik,vision']


def _worker(fmt, out_dir, in_file):
    from Ingram import get_config
    from Ingram.data import Data
    args = argparse.Namespace(
        in_file=in_file, out_dir=out_dir, ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=5, timeout=1,
        disable_snapshot=True, format=fmt, poc=None, exclude_poc=None,
        debug=False, no_resume=True)
    config = get_config(args)
    data = Data(config)
    data.add_vulnerable(VULN)
    data.add_not_vulnerable(NOTV)
    data.__del__()   # flush + close deterministico


def _check(fmt, out_dir):
    csv_v = os.path.join(out_dir, 'results.csv')
    csv_n = os.path.join(out_dir, 'not_vulnerable.csv')
    json_v = os.path.join(out_dir, 'results.json')
    json_n = os.path.join(out_dir, 'not_vulnerable.json')

    want_csv = fmt in ('csv', 'both')
    want_json = fmt in ('json', 'both')

    assert os.path.exists(csv_v) == want_csv, f"{fmt}: results.csv presence"
    assert os.path.exists(json_v) == want_json, f"{fmt}: results.json presence"

    if want_csv:
        line = open(csv_v).read().strip()
        assert line == ','.join(VULN), f"{fmt}: csv content {line!r}"
    if want_json:
        rec = json.loads(open(json_v).read().strip())
        assert rec == {'ip': '1.2.3.4', 'port': '80', 'product': 'dahua',
                       'user': 'admin', 'password': 'pa,ss', 'poc': 'dahua-weak-password'}, f"{fmt}: json {rec}"
        nrec = json.loads(open(json_n).read().strip())
        assert nrec == {'ip': '5.6.7.8', 'port': '81', 'product': 'hik,vision'}, f"{fmt}: json notv {nrec}"


def run_all():
    ok = True
    for fmt in ('csv', 'json', 'both'):
        tmp = tempfile.mkdtemp()
        out_dir = os.path.join(tmp, 'out'); os.makedirs(out_dir)
        in_file = os.path.join(tmp, 'input'); open(in_file, 'w').write("192.168.0.1\n")
        # subprocess pulito per evitare il singleton Data
        r = subprocess.run([sys.executable, __file__, '--worker', fmt, out_dir, in_file],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  FAIL worker {fmt}\n{r.stderr}"); ok = False; continue
        try:
            _check(fmt, out_dir)
            print(f"  ok  format={fmt}")
        except AssertionError as e:
            print(f"  FAIL check {fmt}: {e}"); ok = False
    print("\nOK" if ok else "\nFAILED")
    return ok


if __name__ == '__main__':
    if len(sys.argv) >= 5 and sys.argv[1] == '--worker':
        _worker(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(0 if run_all() else 1)
