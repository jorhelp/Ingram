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


@singleton
class Data:

    def __init__(self, _input, output):
        self.input = _input
        self.output = output
        self.var_lock = RLock()
        self.file_lock = RLock()
        self.create_time = get_current_time()
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
                    if '-' in line or '/' in line:
                        self.total += IPy.IP(line.rstrip(), make_net=True).len()
                    else: self.total += 1

    def preprocess(self):
        # done
        with open(os.path.join(self.output, 'log.txt'), 'r') as f:
            loglines = f.readlines()
            for line in loglines[::-1]:
                if line.strip().endswith('running state'):
                    # check the taskid
                    items = line.split('#@#')
                    if items[-3] == self.taskid:
                        self.done = int(items[-2])
                        break
            del loglines

        
        # the location to begin
        if self.done != 0:
            for _ in range(self.done):
                next(self.ip_generator)
            #  current = 0
            #  while self.lines:
            #      line = self.lines.pop(0)
            #      current += get_ip_seg_len(line)
            #      if current == self.done:
            #          break
            #      elif current < self.done:
            #          continue
            #      else:
            #          ips = get_all_ip(line)
            #          self.lines = ips[-(current - self.done):] + self.lines
            #          break
            #  logger.debug(f"current: {current}, done: {self.done}, total: {self.total}")

        # found
        results_file = os.path.join(self.output, 'results.csv')
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                self.found = len([l for l in f if l.strip()])

        self.vul = open(results_file, 'a')
        self.not_vul = open(os.path.join(self.output, 'not_vulnerable.csv'), 'a')

    def ip_generate(self):
        with open(self.input, 'r') as f:
            for line in f:
                if (not line.startswith('#')) and line.rstrip():
                    if ':' in line:  # ip:port
                        yield line.rstrip()
                    else:
                        for ip in IPy.IP(line.rstrip(), make_net=True):
                            yield ip.strNormal()

    def get_total(self):
        with self.var_lock:
            return self.total

    def get_done(self):
        with self.var_lock:
            return self.done

    def get_found(self):
        with self.var_lock:
            return self.found

    def found_add(self):
        with self.var_lock:
            self.found += 1

    def done_add(self):
        with self.var_lock:
            self.done += 1

    def vul_add(self, item):
        with self.file_lock:
            self.vul.writelines(item)
            self.vul.flush()

    def not_vul_add(self, item):
        with self.file_lock:
            self.not_vul.writelines(item)
            self.not_vul.flush()

    def record_running_state(self):
        # every 5 minutes
        with self.var_lock:
            time_interval = int(get_current_time() - self.create_time)
            if time_interval % (5 * 60) == 0:
                logger.info(f"#@#{self.taskid}#@#{self.done}#@#running state")

    def __del__(self):
        try:  # if dont use try, sys.exit() may cause error
            self.vul.close()
            self.not_vul.close()
        except Exception as e:
            logger.error(e)
