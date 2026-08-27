"""Runner minimale senza dipendenze esterne (pytest non richiesto)."""
import importlib, sys, os, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MODULES = ['tests.test_net', 'tests.test_fingerprint', 'tests.test_config']
total = failed = 0
for modname in MODULES:
    mod = importlib.import_module(modname)
    fns = [v for k, v in sorted(vars(mod).items()) if k.startswith('test_') and callable(v)]
    print(f"\n== {modname} ==")
    for fn in fns:
        total += 1
        try:
            fn(); print(f"  ok  {fn.__name__}")
        except Exception:
            failed += 1
            print(f"  FAIL {fn.__name__}")
            traceback.print_exc()
print(f"\n{'='*40}\n{total-failed}/{total} passed, {failed} failed")
sys.exit(1 if failed else 0)
