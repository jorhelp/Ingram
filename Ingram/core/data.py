"""the data that produced by scanner and send to workshop"""
import os
import IPy
import hashlib
from multiprocessing import Pool

from gevent.lock import RLock

from Ingram.utils import color
from Ingram.utils import logger
from Ingram.utils import singleton
from Ingram.utils import get_current_time
from Ingram.utils import get_all_ip, get_ip_seg_len


@singleton
class Data:

    def __init__(self, _input, output):
        self.input = _input
        self.output = output
        self.var_lock = RLock()
        self.file_lock = RLock()
        self.create_time = get_current_time()
        self.runned_time = 0
        self.taskid = hashlib.md5((self.input + self.output).encode('utf-8')).hexdigest()

        self.total = 0
        self.done = 0
        self.found = 0
        self.ip_generator = self.ip_generate()  # since some ip segment is very big, and maybe oom error

        self.preprocess()

    def get_data_from_disk(self):
        """对于比较耗时的工作，用一个单独的线程放到后台执行"""
        # get total ip
        with open(self.input, 'r') as f:
            for line in f:
                if (not line.startswith('#')) and line.rstrip():
                    self.total += get_ip_seg_len(line.rstrip())

    def preprocess(self):
        # done
        state_file = os.path.join(self.output, f'.{self.taskid}')
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    _done, _runned_time = f.readline().split(',')
                    self.done = int(_done.strip())
                    self.runned_time = float(_runned_time.strip())
            except: pass

        # found
        results_file = os.path.join(self.output, 'results.csv')
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                self.found = len([l for l in f if l.rstrip()])

        self.vul = open(results_file, 'a')
        self.not_vul = open(os.path.join(self.output, 'not_vulnerable.csv'), 'a')

    def ip_generate(self):
        current, remain = 0, []
        with open(self.input, 'r') as f:
            if self.done:
                for line in f:
                    if (not line.startswith('#')) and line.rstrip():
                        current += get_ip_seg_len(line.rstrip())
                        if current == self.done:
                            break
                        elif current < self.done:
                            continue
                        else:
                            ips = get_all_ip(line.rstrip())
                            remain = ips[(self.done - current): ]
                            break

                for ip in remain:
                    yield ip

            for line in f:
                if (not line.startswith('#')) and line.rstrip():
                    for ip in get_all_ip(line.rstrip()):
                        yield ip

    def get_total(self):
        with self.var_lock: return self.total

    def get_done(self):
        with self.var_lock: return self.done

    def get_found(self):
        with self.var_lock: return self.found

    def found_add(self):
        with self.var_lock: self.found += 1

    def done_add(self):
        with self.var_lock: self.done += 1

    def vul_add(self, item):
        with self.file_lock:
            self.vul.writelines(item)
            self.vul.flush()

    def not_vul_add(self, item):
        with self.file_lock:
            self.not_vul.writelines(item)
            self.not_vul.flush()

    def record_running_state(self):
        with open(os.path.join(self.output, f".{self.taskid}"), 'w') as f:
            f.write(f"{str(self.done)},{self.runned_time + get_current_time() - self.create_time}")

    def __del__(self):
        try:  # if dont use try, sys.exit() may cause error
            self.record_running_state()
            self.vul.close()
            self.not_vul.close()
        except Exception as e:
            logger.error(e)
