"""主机存活检测"""
import os
import subprocess

from .common import os_check


def _ping(target: str, nums: int, timeout: int) -> bool:
    # windows 下 -w 是毫秒，linux 下则是秒
    param = f"-w {timeout * 1000} -n" if os_check() == 'windows' else f"-w {timeout} -c"
    dev_null = open(os.devnull, 'w')
    with subprocess.Popen(f"ping {param} {nums} {target}", stdout=subprocess.PIPE, stderr=dev_null, shell=True) as p:
        return 'ttl' in ''.join(map(str, p.stdout.readlines())).lower()


def alive_check(target: str, timeout: int=2) -> bool:
    return _ping(target, 2, timeout)