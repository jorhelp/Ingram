"""Test lettura risultati per il REPORT finale (selezione per formato attivo)."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

from Ingram.core import read_result_rows


def _dir_with(csv=None, js=None):
    d = tempfile.mkdtemp()
    if csv is not None:
        open(os.path.join(d, 'results.csv'), 'w').write(csv)
    if js is not None:
        open(os.path.join(d, 'results.json'), 'w').write(js)
    return d, os.path.join(d, 'results.csv'), os.path.join(d, 'results.json')


def test_csv_format_reads_csv():
    d, c, j = _dir_with(csv='1.2.3.4,80,dahua-x,admin,admin,dahua-weak-password\n')
    assert read_result_rows(c, j, 'csv') == [('dahua-x', 'dahua-weak-password')]


def test_json_format_reads_json():
    d, c, j = _dir_with(js='{"product":"hikvision","poc":"cve-2021-36260"}\n')
    assert read_result_rows(c, j, 'json') == [('hikvision', 'cve-2021-36260')]


def test_json_format_ignores_stale_csv():
    # results.csv residuo da una run precedente NON deve essere letto con -f json
    d, c, j = _dir_with(csv='9.9.9.9,80,stale,u,p,old_poc\n',
                        js='{"product":"hikvision","poc":"fresh_poc"}\n')
    assert read_result_rows(c, j, 'json') == [('hikvision', 'fresh_poc')]


def test_both_prefers_csv():
    d, c, j = _dir_with(csv='1.1.1.1,80,dahua,u,p,poc_csv\n',
                        js='{"product":"hik","poc":"poc_json"}\n')
    assert read_result_rows(c, j, 'both') == [('dahua', 'poc_csv')]


def test_csv_format_falls_back_to_json_if_no_csv():
    d, c, j = _dir_with(js='{"product":"x","poc":"y"}\n')
    assert read_result_rows(c, j, 'csv') == [('x', 'y')]


def test_missing_files_empty():
    d, c, j = _dir_with()
    assert read_result_rows(c, j, 'csv') == []
    assert read_result_rows(c, j, 'json') == []


def test_skips_malformed_json_line():
    d, c, j = _dir_with(js='not-json\n{"product":"x","poc":"y"}\n')
    assert read_result_rows(c, j, 'json') == [('x', 'y')]


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
