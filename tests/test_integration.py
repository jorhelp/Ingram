"""Integrazione: pipeline config -> Data (calcolo totale + generazione IP).
Riproduce lo scenario che prima crashava: range non allineato nel file input.
Eseguire in un processo dedicato (Data e' singleton)."""
import warnings; warnings.filterwarnings('ignore')
from gevent import monkey; monkey.patch_all(thread=False, queue=False)

import argparse, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram import get_config
from Ingram.data import Data
from Ingram.pocs import get_poc_dict


def main():
    tmp = tempfile.mkdtemp()
    in_file = os.path.join(tmp, 'input')
    out_dir = os.path.join(tmp, 'out')
    os.makedirs(os.path.join(out_dir, 'snapshots'))
    with open(in_file, 'w') as f:
        f.write("# commento da ignorare\n")
        f.write("192.168.0.1\n")            # 1
        f.write("10.0.0.0/30\n")            # 4
        f.write("172.16.0.0-172.16.0.10\n") # 11  <-- prima: ValueError

    args = argparse.Namespace(
        in_file=in_file, out_dir=out_dir, ports=None, users=None, passwords=None,
        users_file=None, pass_file=None, th_num=10, timeout=1,
        disable_snapshot=True, debug=False, no_resume=True)
    config = get_config(args)

    data = Data(config)
    expected_total = 1 + 4 + 11
    assert data.total == expected_total, f"total {data.total} != {expected_total}"

    ips = list(data.ip_generator)
    assert len(ips) == expected_total, f"generati {len(ips)} != {expected_total}"
    assert ips[0] == '192.168.0.1'
    assert '10.0.0.3' in ips
    assert '172.16.0.10' in ips

    poc_dict = get_poc_dict(config)
    assert len(poc_dict) > 0 and 'hikvision' in poc_dict

    print(f"integration OK: total={data.total}, ips={len(ips)}, prodotti_poc={len(poc_dict)}")


if __name__ == '__main__':
    main()
