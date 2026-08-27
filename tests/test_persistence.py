"""Regressione: i record not_vulnerable devono sopravvivere all'uscita del
processo figlio (fork -> os._exit salta __del__/close/flush).

Riproduce il modello di run_ingram: Data e' costruito nel parent, la scansione
gira in un multiprocessing.Process che ritorna normalmente."""
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

import argparse
import os
import sys
import tempfile
from multiprocessing import Process

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram import get_config
from Ingram.data import Data

N = 10  # non multiplo di 50: con il vecchio batch-flush andrebbe perso tutto


def _writer(data):
    for i in range(N):
        data.add_not_vulnerable([f'10.0.0.{i}', '80', 'prod'])
    # ritorno normale -> il figlio esce via os._exit(), nessuna finalizzazione


def main():
    tmp = tempfile.mkdtemp()
    out_dir = os.path.join(tmp, 'out'); os.makedirs(out_dir)
    in_file = os.path.join(tmp, 'input'); open(in_file, 'w').write("192.168.0.1\n")
    args = argparse.Namespace(
        in_file=in_file, out_dir=out_dir, ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=5, timeout=1,
        disable_snapshot=True, format='both', poc=None, exclude_poc=None,
        debug=False, no_resume=True)
    config = get_config(args)
    data = Data(config)                       # file aperti nel PARENT

    p = Process(target=_writer, args=(data,))  # scrittura nel figlio (fork)
    p.start(); p.join()

    csv_lines = [l for l in open(os.path.join(out_dir, 'not_vulnerable.csv')) if l.strip()]
    json_lines = [l for l in open(os.path.join(out_dir, 'not_vulnerable.json')) if l.strip()]
    assert len(csv_lines) == N, f"csv: attesi {N}, trovati {len(csv_lines)} (buffer perso su os._exit?)"
    assert len(json_lines) == N, f"json: attesi {N}, trovati {len(json_lines)}"
    print(f"persistence OK: not_vulnerable csv={len(csv_lines)} json={len(json_lines)} sopravvissuti a os._exit()")


if __name__ == '__main__':
    main()
