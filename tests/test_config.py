"""Test caricamento config e credenziali (senza rete)."""
import sys, os, tempfile, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# reset del modulo config tra i test perché _config è a livello di modulo
def fresh_get_config(**ns):
    import importlib
    import Ingram.config as cfg
    importlib.reload(cfg)
    args = argparse.Namespace(
        in_file='x', out_dir='y', ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=150, timeout=3,
        disable_snapshot=False, debug=False, no_resume=False)
    for k, v in ns.items():
        setattr(args, k, v)
    return cfg.get_config(args)


def test_defaults():
    c = fresh_get_config()
    assert c.users == ['admin']
    assert 'admin' in c.passwords and '' in c.passwords
    assert c.no_resume is False          # bug precedente: chiave assente
    assert len(c.rules) > 0


def test_cli_lists_override():
    c = fresh_get_config(users=['root', 'guest'], passwords=['x'])
    assert c.users == ['root', 'guest']
    assert c.passwords == ['x']


def test_files_load():
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as uf:
        uf.write("# commento\nadmin\nroot\n\noperator\n"); upath = uf.name
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as pf:
        pf.write("pass1\npass2\n"); ppath = pf.name
    c = fresh_get_config(users_file=upath, pass_file=ppath)
    assert c.users == ['admin', 'root', 'operator']   # commento e riga vuota ignorati
    assert c.passwords == ['pass1', 'pass2']
    assert not hasattr(c, 'users_file')               # non deve inquinare la config
    os.unlink(upath); os.unlink(ppath)


def test_cli_list_beats_file():
    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as uf:
        uf.write("fromfile\n"); upath = uf.name
    c = fresh_get_config(users_file=upath, users=['fromcli'])
    assert c.users == ['fromcli']
    os.unlink(upath)


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
