"""Test output strutturato + selezione POC (in-process, senza rete)."""
import argparse
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# monkeypatch necessario perche' i POC importano requests/gevent-friendly libs
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)


def _fresh_config(**ns):
    import Ingram.config as cfg
    importlib.reload(cfg)
    args = argparse.Namespace(
        in_file='x', out_dir='y', ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=10, timeout=1,
        disable_snapshot=True, format='csv', poc=None, exclude_poc=None,
        debug=False, no_resume=True)
    for k, v in ns.items():
        setattr(args, k, v)
    return cfg.get_config(args)


def _poc_dict(**ns):
    cfg = _fresh_config(**ns)
    import Ingram.pocs as pocs
    return pocs.get_poc_dict(cfg)


def test_json_line_maps_fields():
    from Ingram.data import json_line, VULN_FIELDS
    line = json_line(VULN_FIELDS, ['1.2.3.4', '80', 'dahua', 'admin', 'admin', 'dahua-weak-password'])
    rec = json.loads(line)
    assert rec == {'ip': '1.2.3.4', 'port': '80', 'product': 'dahua',
                   'user': 'admin', 'password': 'admin', 'poc': 'dahua-weak-password'}


def test_json_line_handles_comma_in_value():
    # il CSV si romperebbe; il JSON no
    from Ingram.data import json_line, NOT_VULN_FIELDS
    rec = json.loads(json_line(NOT_VULN_FIELDS, ['1.2.3.4', '80', 'weird,product']))
    assert rec['product'] == 'weird,product'


def test_poc_dict_all_by_default():
    d = _poc_dict()
    assert 'hikvision' in d and 'dahua' in d
    assert len(d) >= 10


def test_poc_dict_include_by_pocname():
    d = _poc_dict(poc=['dahua-weak-password'])
    assert list(d.keys()) == ['dahua']
    names = [p.name for p in d['dahua']]
    assert names == ['dahua-weak-password']   # solo quel POC, non gli altri dahua


def test_poc_dict_include_by_product():
    d = _poc_dict(poc=['hikvision'])
    assert list(d.keys()) == ['hikvision']
    assert len(d['hikvision']) >= 2           # tutti i POC hikvision


def test_poc_dict_exclude_product():
    d = _poc_dict(exclude_poc=['dahua'])
    assert 'dahua' not in d
    assert 'hikvision' in d


def test_poc_dict_exclude_pocname():
    full = _poc_dict()['dahua']
    d = _poc_dict(exclude_poc=['dahua-weak-password'])
    remaining = [p.name for p in d.get('dahua', [])]
    assert 'dahua-weak-password' not in remaining
    assert len(remaining) == len(full) - 1


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
