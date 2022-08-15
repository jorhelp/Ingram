"""input output"""
import os
import sys
import pickle
import hashlib
from multiprocessing import Pool, Queue

from gevent.lock import RLock

from Ingram.utils import color
from Ingram.utils import logger
from Ingram.utils import singleton
from Ingram.utils import get_ip_seg_len, get_all_ip


@singleton
class Data:

    def __init__(self, _input, output):
        self.input = _input
        self.output = output
        self.msg_queue = Queue()
        self.var_lock = RLock()
        self.file_lock = RLock()
        self.taskid = hashlib.md5((self.input + self.output).encode('utf-8')).hexdigest()

        self.total = 0
        self.done = 0
        self.found = 0
        self.ip_generator = self.ip_generate()  # since some ip segment is very big, and maybe oom error

        self.preprocess()

    def preprocess(self):
        if not os.path.isfile(self.input):
            print(color.red(f"the input file {self.input} does not exists!"))
            exit(0)

        if not os.path.exists(self.output):
            os.mkdir(self.output)

        with open(self.input, 'r') as f:
            self.lines = [l.strip() for l in f if not l.startswith('#') and l.strip()]
        if len(self.lines) == 0:
            print(color.red(f"the input file {self.input} has nothing to scan!"))

        # total
        with Pool(processes=None) as pool:
            self.total = sum(pool.map_async(get_ip_seg_len, self.lines).get())

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
            current = 0
            while self.lines:
                line = self.lines.pop(0)
                current += get_ip_seg_len(line)
                if current == self.done:
                    break
                elif current < self.done:
                    continue
                else:
                    ips = get_all_ip(line)
                    self.lines = ips[-(current - self.done):] + self.lines
                    break
            logger.debug(f"current: {current}, done: {self.done}, total: {self.total}")

        # found
        results_file = os.path.join(self.output, 'results.csv')
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                self.found = len([l for l in f if l.strip()])

        self.vuls = open(results_file, 'a')
        self.not_vuls = open(os.path.join(self.output, 'not_vulnerable.csv'), 'a')

    def ip_generate(self):
        for line in self.lines:
            ips = get_all_ip(line)
            for ip in ips:
                yield ip

    def __del__(self):
        try:  # if dont add try, sys.exit() may cause error
            self.vuls.close()
            self.not_vuls.close()
            self.msg_queue.close()
        except Exception as e:
            logger.error(e)
