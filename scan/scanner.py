"""Scanners"""
import os
import sys
import time
from multiprocessing import Lock
from collections import defaultdict

CWD = os.path.dirname(__file__)
sys.path.append(os.path.join(CWD, '..'))
from scan.modules import modules
from utils.net import get_all_ip, get_ip_seg_len
from utils.base import multi_thread, process_bar, save_res, printf
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
        self.done_lock = Lock()
        self.found_lock = Lock()
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
            total_ip = list(set(total_ip))
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
        if os.path.exists(os.path.join(self.args.out_path, PAUSE)): self.paused.close()


    def report(self):
        """report the results"""
        if not os.path.exists(os.path.join(self.args.out_path, RESULTS_ALL)):
            return

        with open(os.path.join(self.args.out_path, RESULTS_ALL), 'r') as f:
            items = [l.strip().split(',') for l in f if l.strip()]

        results = defaultdict(lambda: defaultdict(lambda: 0))
        for i in items:
            dev, vul = i[-2], i[-1]
            results[dev][vul] += 1
        results_sum = len(items)
        results_max = max([val for vul in results.values() for val in vul.values()])
        
        print('\n')
        print('-' * 19, 'REPORT', '-' * 19)
        for dev in results:
            vuls = [(vul_name, vul_count) for vul_name, vul_count in results[dev].items()]
            dev_sum = sum([i[1] for i in vuls])
            printf(f"{dev} {dev_sum}", color='red', bold=True)
            for vul_name, vul_count in vuls:
                printf(f"{vul_name:>18} | ", end='')
                block_num = int(vul_count / results_max * 25)
                printf('▥' * block_num, end=' ')
                printf(vul_count)
        printf(f"{'sum: ' + str(results_sum):>46}", color='yellow', flash=True)
        print('-' * 46)
        print('\n')


    def scan_meta(self, ip, mod_name):
        found = False
        try:
            res = self.modules[mod_name](ip)
            if res[0] == True:  # found vulnerability
                found = True
                with self.found_lock: self.found += 1
                if ':' not in ip: port = '80'
                else: ip, port = ip.split(':')
                camera_info = [ip, port] + res[1:]
                save_res(camera_info, os.path.join(self.args.out_path, RESULTS_ALL))  # save results (all)
                if res[1]:
                    save_res([ip, port] + res[1: 3], os.path.join(self.args.out_path, RESULTS_SIMPLE))  # save [ip, port, user, pass]
                
                # save snapshot if possible
                if self.args.nosnap:
                    os.system(f"python3 -Bu utils/camera.py --ip '{camera_info[0]}'"
                                f" --port '{camera_info[1]}' --user '{camera_info[2]}' --passwd '{camera_info[3]}'"
                                f" --device '{camera_info[4]}' --vulnerability '{camera_info[5]}'"
                                f" --sv_path {self.args.out_path} > /dev/null 2> /dev/null")
        except Exception as e:
            if DEBUG: print(e)
        finally:
            return found


    def mod_by_device(self, dev_type):
        """check if we should scan this device-type or not"""
        if dev_type == 'hikvision':
            for mod_name in ['hik_weak', 'hb_weak', 'cve_2017_7921', 'cve_2021_36260']:
                if mod_name in self.modules: return True
            return False
        if dev_type == 'dahua':
            for mod_name in ['dahua_weak', 'cve_2021_33044']:
                if mod_name in self.modules: return True
            return False
        if dev_type == 'cctv':
            return 'cctv_weak' in self.modules
        if dev_type == 'dlink':
            return 'cve_2020_25078' in self.modules


    def scan(self, ip_term: str):
        if ':' in ip_term: _targets = [ip_term]
        else: _targets = get_all_ip(ip_term)
        for ip in _targets:
            found = False
            dev_type = modules['device_type'](ip)  # hikvision, dahua, cctv, dlink, unidentified

            if dev_type == 'hikvision' and self.mod_by_device('hikvision'):
                if 'hik_weak' in self.modules: found |= self.scan_meta(ip, 'hik_weak')
                if 'hb_weak' in self.modules: found |= self.scan_meta(ip, 'hb_weak')
                if 'cve_2017_7921' in self.modules: found |= self.scan_meta(ip, 'cve_2017_7921')
                if 'cve_2021_36260' in self.modules: found |= self.scan_meta(ip, 'cve_2021_36260')
            elif dev_type == 'dahua' and self.mod_by_device('dahua'):
                if 'dahua_weak' in self.modules: found |= self.scan_meta(ip, 'dahua_weak')
                if 'cve_2021_33044' in self.modules: found |= self.scan_meta(ip, 'cve_2021_33044')
            elif dev_type == 'cctv' and self.mod_by_device('cctv'):
                if 'cctv_weak' in self.modules: found |= self.scan_meta(ip, 'cctv_weak')
            elif dev_type == 'dlink' and self.mod_by_device('dlink'):
                if 'cve_2020_25078' in self.modules: found |= self.scan_meta(ip, 'cve_2020_25078')

            if not found and dev_type != 'unidentified':
                save_res([ip, dev_type], os.path.join(self.args.out_path, RESULTS_FAILED))

            with self.done_lock:
                self.done += 1
                # self.bar(self.total, self.done + 1, self.found, timer=True, start_time=self.start_time)
                self.bar(self.total, self.done, self.found, timer=True, start_time=self.start_time)

        # write paused
        with self.file_lock:
            self.paused.write(ip_term + '\n')
            self.paused.flush()


    def _close(self):
        os.remove(os.path.join(self.args.out_path, PAUSE))


    def __call__(self):
        self.modules = {}

        if self.args.all:
            self.modules = modules
        else:
            for mod_name, mod_func in modules.items():
                if mod_name in self.args and eval(f"self.args.{mod_name}"):
                    self.modules[mod_name] = mod_func
        
        multi_thread(self.scan, self.ip_list, processes=self.args.th_num)
        self.report()
        self._close()
