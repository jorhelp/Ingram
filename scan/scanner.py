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
    def __init__(self, args) -> None:
        self.args = args
        self.scanner_name = 'base'  # Need to be respecified in subclass
        if not os.path.isdir(args.out_path):
            os.mkdir(args.out_path)


class MasScaner(Base):
    """This scanner need root authority"""
    def __init__(self, args) -> None:
        super().__init__(args)
        self.scanner_name = 'masscan'
        self.tmp = os.path.join(self.args.out_path, MASSCAN_TMP)  # temp out file

    def parse(self, tmp: str='tmp') -> None:
        with open(tmp, 'r') as tf:
            with open(os.path.join(self.args.out_path, MASSCAN_RES), 'w') as of:
                for line in tf:
                    if 'open' in line:
                        items = line.split()
                        ip, port = items[-2], items[2]
                        of.write(f"{ip}:{port}\n")

    def __call__(self) -> None:
        if os.path.exists('paused.conf'):
            os.system(f"sudo masscan --exclude 255.255.255.255 --resume paused.conf")
        else:
            os.system(f"sudo masscan --exclude 255.255.255.255 -iL {self.args.in_file} -p{self.args.port} --rate {self.args.rate} -oL {self.tmp}")
        self.parse(self.tmp)


class CameraScanner(Base):

    def __init__(self, args) -> None:
        super().__init__(args)
        self.scanner_name = 'camera scanner'
        self.thread_lock = Lock()
        self.file_lock = Lock()
        self.start_time = time.time()
        self.bar = process_bar()

        self._preprocess()

    def _preprocess(self):
        self.total = 0
        self.found = 0
        self.done = 0

        # total ip
        with open(self.args.in_file, 'r') as f:
            total_ip = [l.strip() for l in f if not l.startswith('#') and l.strip()]
        for ip in total_ip:
            self.total += get_ip_seg_len(ip) if '-' in ip or '/' in ip else 1

        # processed ip
        if not os.path.exists(os.path.join(self.args.out_path, PAUSE)):
            self.paused = open(os.path.join(self.args.out_path, PAUSE), 'a')
            processed_ip = []
        else:
            self.paused = open(os.path.join(self.args.out_path, PAUSE), 'r+')
            processed_ip = [l.strip() for l in self.paused if not l.startswith('#') and l.strip()]
            for ip in processed_ip:
                self.done += get_ip_seg_len(ip) if '-' in ip or '/' in ip else 1
        
        # need scan
        self.ip_list = list(set(total_ip) - set(processed_ip)) if processed_ip else total_ip

        # found
        if os.path.exists(os.path.join(self.args.out_path, RESULTS_ALL)):
            with open(os.path.join(self.args.out_path, RESULTS_ALL), 'r') as f:
                for line in f:
                    if not line.startswith('#') and line.strip():
                        self.found += 1

    def __del__(self):
        self.paused.close()

    def _step(self, *args, **kwargs):
        with self.thread_lock:
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
                        save_res(camera_info, os.path.join(self.args.out_path, RESULTS_ALL))  # save result
                        os.system(f"python3 -Bu utils/camera.py --ip '{camera_info[0]}'"
                                  f" --port '{camera_info[1]}' --user '{camera_info[2]}' --passwd '{camera_info[3]}'"
                                  f" --device '{camera_info[4]}' --vulnerability '{camera_info[5]}'"
                                  f" --sv_path {self.args.out_path} > /dev/null 2> /dev/null")  # save snapshot if possible
                except Exception as e: 
                    if DEBUG: print(e)
                finally: self._step(found=found)
            with self.thread_lock: self.done += 1
        # write paused
        with self.file_lock:
            self.paused.write(ip_term + '\n')
            self.paused.flush()

    def _close(self):
        os.remove(os.path.join(self.args.out_path, PAUSE))

    def __call__(self):
        self.modules = []
        hik_weak_partial = partial(hik_weak, users=USERS, passwords=PASSWORDS)
        dahua_weak_partial = partial(dahua_weak, users=USERS, passwords=PASSWORDS)
        cctv_weak_partial = partial(cctv_weak, users=USERS, passwords=PASSWORDS)
        hb_weak_partial = partial(hb_weak, users=USERS, passwords=PASSWORDS)

        if self.args.all:
            self.modules.extend([cve_2017_7921, cve_2021_36260, cve_2020_25078, cve_2021_33044])
            self.modules.extend([hik_weak_partial, dahua_weak_partial, cctv_weak_partial, hb_weak_partial])
        else:
            if self.args.hik_weak: self.modules.append(hik_weak_partial)
            if self.args.dahua_weak: self.modules.append(dahua_weak_partial)
            if self.args.cctv_weak: self.modules.append(cctv_weak_partial)
            if self.self.args.hb_weak: self.modules.append(hb_weak_partial)
            if self.args.cve_2017_7921: self.modules.append(cve_2017_7921)
            if self.args.cve_2021_36260: self.modules.append(cve_2021_36260)
            if self.args.cve_2020_25078: self.modules.append(cve_2020_25078)
            if self.args.cve_2021_33044: self.modules.append(cve_2021_33044)
        
        multi_thread(self.scan, self.ip_list, processes=self.args.th_num)
        self._close()
