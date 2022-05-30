"""Scanners"""
import os
import sys
import time
from functools import partial
from multiprocessing import Lock

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from scan.modules import *
from utils.net import get_all_ip, get_ip_seg_len
from utils.base import multi_thread, process_bar, save_res
from utils.config import *


class Base:
    """Base class"""
    def __init__(self, in_file: str, out_path: str) -> None:
        self.in_file = in_file
        self.out_path = out_path
        self.scanner_name = 'base'  # Need to be respecified in subclass
        if not os.path.isdir(out_path):
            os.mkdir(out_path)


class MasScaner(Base):
    """This scanner need root authority"""
    def __init__(self, in_file: str, out_path: str) -> None:
        super().__init__(in_file, out_path)
        self.scanner_name = 'masscan'
        self.tmp = os.path.join(out_path, 'tmp')  # temp out file

    def parse(self, tmp: str='tmp') -> None:
        with open(tmp, 'r') as tf:
            with open(os.path.join(self.out_path, 'masscan_res'), 'w') as of:
                for line in tf:
                    if 'open' in line:
                        items = line.split()
                        ip, port = items[-2], items[2]
                        of.write(f"{ip}:{port}\n")

    def __call__(self, args) -> None:
        os.system(f"sudo masscan --exclude 255.255.255.255 -iL {self.in_file} -p{args.port} --rate {args.rate} -oL {self.tmp}")
        self.parse(self.tmp)


class CameraScanner(Base):

    def __init__(self, in_file: str, out_path: str) -> None:
        super().__init__(in_file, out_path)
        self.scanner_name = 'camera scanner'
        self.lock = Lock()
        self.ip_list = []
        self.total = 0
        self.found = 0
        self.done = 0
        self.start_time = time.time()
        self.bar = process_bar()

        self._get_ip()

    def _get_ip(self):
        """get ip / ip segment, and count the number"""
        with open(self.in_file, 'r') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    self.total += get_ip_seg_len(line.strip()) if '-' in line or '/' in line else 1
                    self.ip_list.append(line.strip())

    def _step(self, *args, **kwargs):
        with self.lock:
            if kwargs['found']:
                self.found += 1
            self.bar(self.total, self.done + 1, self.found, timer=True, start_time=self.start_time)

    def scan(self, ip_term: str):
        if ':' in ip_term: _targets = [ip_term]
        else: _targets = get_all_ip(ip_term)
        for ip in _targets:
            for mod in self.modules:
                found = False
                try:
                    res = mod(ip)
                    if res[0] == True:  # found vulnerability
                        found = True
                        if ':' not in ip: port = '80'
                        else: ip, port = ip.split(':')
                        camera_info = [ip, port] + res[1:]
                        save_res(camera_info, self.out_path)  # save result
                        os.system(f"python3 -Bu utils/camera.py --ip '{camera_info[0]}'"
                                  f" --port '{camera_info[1]}' --user '{camera_info[2]}' --passwd '{camera_info[3]}'"
                                  f" --device '{camera_info[4]}' --vulnerability '{camera_info[5]}'"
                                  f" --sv_path {self.out_path} > /dev/null 2> /dev/null")  # save snapshot if possible
                except Exception as e: pass
                finally: self._step(found=found)
            with self.lock: self.done += 1


    def __call__(self, args):
        self.modules = []
        hik_weak_partial = partial(hik_weak, users=USERS, passwords=PASSWORDS)
        dahua_weak_partial = partial(dahua_weak, users=USERS, passwords=PASSWORDS)
        cctv_weak_partial = partial(cctv_weak, users=USERS, passwords=PASSWORDS)
        hb_weak_partial = partial(hb_weak, users=USERS, passwords=PASSWORDS)

        if args.all:
            self.modules.extend([cve_2017_7921, cve_2021_36260, cve_2020_25078, cve_2021_33044])
            self.modules.extend([hik_weak_partial, dahua_weak_partial, cctv_weak_partial, hb_weak_partial])
        else:
            if args.hik_weak: self.modules.append(hik_weak_partial)
            if args.dahua_weak: self.modules.append(dahua_weak_partial)
            if args.cctv_weak: self.modules.append(cctv_weak_partial)
            if args.hb_weak: self.modules.append(hb_weak_partial)
            if args.cve_2017_7921: self.modules.append(cve_2017_7921)
            if args.cve_2021_36260: self.modules.append(cve_2021_36260)
            if args.cve_2020_25078: self.modules.append(cve_2020_25078)
            if args.cve_2021_33044: self.modules.append(cve_2021_33044)
        
        multi_thread(self.scan, self.ip_list, processes=args.th_num)
