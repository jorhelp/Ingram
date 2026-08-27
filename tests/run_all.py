"""Runner della suite (nessuna dipendenza esterna, pytest non richiesto).

Esegue i moduli di test in-process e gli script standalone (che usano
subprocess perche' Data/Core sono singleton). Uscita != 0 su qualsiasi errore.

    python3 tests/run_all.py
"""
import importlib
import os
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

IN_PROCESS = [
    'tests.test_net',
    'tests.test_fingerprint',
    'tests.test_config',
    'tests.test_output',
    'tests.test_loader',
    'tests.test_report',
    'tests.test_findings',
]
STANDALONE = [
    'tests/test_integration.py',
    'tests/test_output_files.py',
    'tests/test_persistence.py',
]

total = failed = 0

for modname in IN_PROCESS:
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

for script in STANDALONE:
    total += 1
    print(f"\n== {script} ==")
    r = subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), script)],
                       capture_output=True, text=True)
    body = '\n'.join(l for l in r.stdout.splitlines() if 'INFO     | Ingram' not in l)
    print(body)
    if r.returncode != 0:
        failed += 1
        print(f"  FAIL (exit {r.returncode})\n{r.stderr}")

print(f"\n{'='*40}\n{total-failed}/{total} passed, {failed} failed")
sys.exit(1 if failed else 0)
