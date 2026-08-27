"""Test arricchimento report: severità + descrizione per finding."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

from Ingram.core import build_findings, LEVEL_LABEL


def test_maps_level_and_desc():
    meta = {'cve-x': ('高', '  command   injection\n  full compromise '),
            'weak': ('低', '')}
    out = build_findings(['cve-x', 'weak'], meta)
    assert out[0] == ('HIGH', 'cve-x', 'command injection full compromise')  # spazi normalizzati
    assert out[1] == ('LOW', 'weak', '')


def test_dedup_preserves_first_order():
    meta = {'a': ('中', 'x'), 'b': ('低', 'y')}
    out = build_findings(['a', 'b', 'a', 'b'], meta)
    assert [d[1] for d in out] == ['a', 'b']


def test_unknown_poc_falls_back():
    out = build_findings(['mistero'], {})
    assert out == [('?', 'mistero', '')]


def test_long_desc_truncated():
    meta = {'p': ('高', 'z' * 500)}
    label, name, desc = build_findings(['p'], meta)[0]
    assert len(desc) == 200 and desc.endswith('...')


def test_real_pocs_have_severity_and_desc():
    # verifica end-to-end: i POC reali espongono level/desc utilizzabili
    import argparse, importlib
    import Ingram.config as cfg; importlib.reload(cfg)
    from Ingram.pocs import get_poc_dict
    args = argparse.Namespace(
        in_file='x', out_dir='y', ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=5, timeout=1,
        disable_snapshot=True, format='csv', poc=None, exclude_poc=None,
        debug=False, no_resume=True)
    config = cfg.get_config(args)
    poc_meta = {}
    for pocs in get_poc_dict(config).values():
        for poc in pocs:
            poc_meta[poc.name] = (poc.level, poc.desc or '')
    # un CVE noto deve avere severità HIGH e una descrizione non vuota
    findings = {f[1]: f for f in build_findings(list(poc_meta), poc_meta)}
    assert 'cve-2021-36260' in findings
    label, _, desc = findings['cve-2021-36260']
    assert label == 'HIGH'
    assert 'command injection' in desc.lower() and len(desc) > 0


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
