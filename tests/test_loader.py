"""Il loader dei POC deve isolare i moduli difettosi (fix di robustezza).
Crea un POC volutamente rotto, verifica in subprocess che l'import non crashi."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BROKEN = os.path.join(ROOT, 'Ingram', 'pocs', '_zzz_broken_test.py')

CHILD = r'''
import warnings; warnings.filterwarnings("ignore")
from gevent import monkey; monkey.patch_all(thread=False, queue=False)
import Ingram.pocs as pocs
from Ingram.pocs.base import POCTemplate
names = [name for name, _ in pocs.load_errors]
assert "_zzz_broken_test" in names, f"broken POC not isolated: {names}"
assert len(POCTemplate.poc_classes) >= 10, "normal POCs failed to load"
print("child OK: broken isolated, normal POCs loaded =", len(POCTemplate.poc_classes))
'''


def test_broken_poc_is_isolated():
    with open(BROKEN, 'w') as f:
        f.write("raise ImportError('boom - intentionally broken test POC')\n")
    try:
        r = subprocess.run([sys.executable, '-c', CHILD], cwd=ROOT,
                           capture_output=True, text=True)
        assert r.returncode == 0, f"import crashed:\nSTDOUT{r.stdout}\nSTDERR{r.stderr}"
        assert 'child OK' in r.stdout, r.stdout
    finally:
        for p in (BROKEN, BROKEN + 'c'):
            if os.path.exists(p):
                os.remove(p)
        cache = os.path.join(ROOT, 'Ingram', 'pocs', '__pycache__')
        if os.path.isdir(cache):
            for f in os.listdir(cache):
                if f.startswith('_zzz_broken_test'):
                    os.remove(os.path.join(cache, f))


if __name__ == '__main__':
    test_broken_poc_is_isolated()
    print("  ok  test_broken_poc_is_isolated")
