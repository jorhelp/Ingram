"""Scanners"""
import os
import sys
import time
from functools import partial
from multiprocessing import Lock

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from scan.modules import *
from utils.net import get_all_ip
from utils.base import multi_thread, multi_process, process_bar, save_res


class Base:
    """Base class"""
    def __init__(self, in_file: str, out_file: str) -> None:
        self.in_file = in_file
        self.out_file = out_file
        self.scanner_name = 'base'  # Need to be respecified in subclass


class MasScaner(Base):
    """This scanner need root authority"""
    def __init__(self, in_file: str, out_file: str) -> None:
        super().__init__(in_file, out_file)
        self.scanner_name = 'masscan'
        self.tmp = 'tmp'  # temp out file

    def parse(self, tmp: str='tmp') -> None:
        with open(tmp, 'r') as tf:
            with open(self.out_file, 'w') as of:
                for i in [line.split()[-2] for line in tf if not line.startswith('#')]:
                    of.write(i + '\n')

    def __call__(self, args) -> None:
        os.system(f"sudo masscan -iL {self.in_file} -p{args.port} --rate {args.rate} -oL {self.tmp}")
        self.parse(self.tmp)


class CameraScanner(Base):

    def __init__(self, in_file: str, out_file: str) -> None:
        super().__init__(in_file, out_file)
        self.scanner_name = 'camera scanner'
        self.ip_list = []
        self.lock = Lock()
        self.total = 0
        self.found = 0
        self.done = 0
        self.start_time = time.time()

        self._get_ip()

    def _get_ip(self):
        with open(self.in_file, 'r') as f:
            for line in f:
                if line.strip():
                    if '-' in line or '/' in line:
                        self.ip_list.extend(get_all_ip(line.strip()))
                    else:
                        self.ip_list.append(line.strip())
        self.total = len(self.ip_list)

    def _step(self, *args, **kwargs):
        with self.lock:
            if kwargs['found']:
                self.found += 1
            process_bar(self.total, self.done, self.found, timer=True, start_time=self.start_time)

    def scan(self, ip):
        for mod in self.modules:
            found = False
            try:
                res = mod(ip)
                if res[0]:
                    found = True
                    save_res(self.out_file, [ip] + res[1:])
            except Exception as e: pass  # print(e)
            finally: self._step(found=found)
        self.done += 1


    def __call__(self, args):
        self.modules = []
        hik_weak_partial = partial(hik_weak, users=args.users, passwords=args.passwords)
        dahua_weak_partial = partial(dahua_weak, users=args.users, passwords=args.passwords)
        if args.all:
            self.modules.extend([cve_2017_7921, cve_2021_36260, cve_2020_25078, hik_weak_partial, dahua_weak_partial])
        else:
            if args.hik_weak: self.modules.append(hik_weak_partial)
            if args.dahua_weak: self.modules.append(dahua_weak_partial)
            if args.cve_2017_7921: self.modules.append(cve_2017_7921)
            if args.cve_2021_36260: self.modules.append(cve_2021_36260)
            if args.cve_2020_25078: self.modules.append(cve_2020_25078)
        multi_thread(self.scan, self.ip_list, processes=args.th_num)
