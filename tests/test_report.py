"""Test lettura risultati per il REPORT finale (CSV vs JSON-only)."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

from Ingram.core import read_result_rows


def _tmp(name, content):
    d = tempfile.mkdtemp()
    p = os.path.join(d, name)
    if content is not None:
        open(p, 'w').write(content)
    return d, p


def test_reads_csv():
    d, csvp = _tmp('results.csv', '1.2.3.4,80,dahua-x,admin,admin,dahua-weak-password\n')
    rows = read_result_rows(csvp, os.path.join(d, 'results.json'))
    assert rows == [('dahua-x', 'dahua-weak-password')]


def test_reads_json_when_no_csv():
    d = tempfile.mkdtemp()
    jsonp = os.path.join(d, 'results.json')
    open(jsonp, 'w').write('{"ip":"1.2.3.4","port":"80","product":"hikvision","user":"a","password":"b","poc":"cve-2021-36260"}\n')
    rows = read_result_rows(os.path.join(d, 'results.csv'), jsonp)
    assert rows == [('hikvision', 'cve-2021-36260')]


def test_csv_preferred_over_json():
    d = tempfile.mkdtemp()
    csvp = os.path.join(d, 'results.csv'); open(csvp, 'w').write('1.1.1.1,80,dahua,u,p,poc_csv\n')
    jsonp = os.path.join(d, 'results.json'); open(jsonp, 'w').write('{"product":"hik","poc":"poc_json"}\n')
    rows = read_result_rows(csvp, jsonp)
    assert rows == [('dahua', 'poc_csv')]


def test_missing_files_empty():
    d = tempfile.mkdtemp()
    assert read_result_rows(os.path.join(d, 'results.csv'), os.path.join(d, 'results.json')) == []


def test_skips_malformed_json_line():
    d = tempfile.mkdtemp()
    jsonp = os.path.join(d, 'results.json')
    open(jsonp, 'w').write('not-json\n{"product":"x","poc":"y"}\n')
    rows = read_result_rows(os.path.join(d, 'results.csv'), jsonp)
    assert rows == [('x', 'y')]


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
