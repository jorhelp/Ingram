"""数据流"""
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Lock, RLock, Thread

from loguru import logger

from .utils import common
from .utils import timer
from .utils import net


@common.singleton
class Data:

    def __init__(self, config):
        self.config = config
        self.create_time = timer.get_time_stamp()
        self.runned_time = 0
        self.taskid = hashlib.md5((self.config.in_file + self.config.out_dir).encode('utf-8')).hexdigest()

        self.total = 0
        self.done = 0
        self.found = 0

        self.total_lock = Lock()
        self.found_lock = Lock()
        self.done_lock = Lock()
        self.vulnerable_lock = Lock()
        self.not_vulneralbe_lock = Lock()

        self.preprocess()

    def _load_state_from_disk(self):
        """加载上次运行状态"""
        # done & found & run time
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                if line := f.readline().strip():
                    _done, _found, _runned_time = line.split(',')
                    self.done = int(_done)
                    self.found = int(_found)
                    self.runned_time = float(_runned_time)

    def _cal_total(self):
        """计算目标总数"""
        with open(self.config.in_file, 'r') as f:
            for line in f:
                if (strip_line := line.strip()) and not line.startswith('#'):
                    self.add_total(net.get_ip_seg_len(strip_line))

    def _generate_ip(self):
        current, remain = 0, []
        with open(self.config.in_file, 'r') as f:
            if self.done:
                for line in f:
                    if (strip_line := line.strip()) and not line.startswith('#'):
                        current += net.get_ip_seg_len(strip_line)
                        if current == self.done:
                            break
                        elif current < self.done:
                            continue
                        else:
                            ips = net.get_all_ip(strip_line)
                            remain = ips[(self.done - current):]
                            break
                for ip in remain:
                    yield ip

            for line in f:
                if (strip_line := line.strip()) and not line.startswith('#'):
                    for ip in net.get_all_ip(strip_line):
                        yield ip

    def preprocess(self):
        """预处理"""
        # 打开记录结果的文件
        self.vulnerable = open(os.path.join(self.config.out_dir, self.config.vulnerable), 'a')
        self.not_vulneralbe = open(os.path.join(self.config.out_dir, self.config.not_vulnerable), 'a')

        self._load_state_from_disk()

        cal_thread = Thread(target=self._cal_total)
        cal_thread.start()

        self.ip_generator = self._generate_ip()
        cal_thread.join()

    def add_total(self, item=1):
        if isinstance(item, int):
            with self.total_lock:
                self.total += item
        elif isinstance(item, list):
            with self.total_lock:
                self.total += sum(item)

    def add_found(self, item=1):
        if isinstance(item, int):
            with self.found_lock:
                self.found += item
        elif isinstance(item, list):
            with self.found_lock:
                self.found += sum(item)

    def add_done(self, item=1):
        if isinstance(item, int):
            with self.done_lock:
                self.done += item
        elif isinstance(item, list):
            with self.done_lock:
                self.done += sum(item)

    def add_vulnerable(self, item):
        with self.vulnerable_lock:
            self.vulnerable.writelines(','.join(item) + '\n')
            self.vulnerable.flush()

    def add_not_vulnerable(self, item):
        with self.not_vulneralbe_lock:
            self.not_vulneralbe.writelines(','.join(item) + '\n')
            self.not_vulneralbe.flush()

    def record_running_state(self):
        # 每隔 20 个记录一下当前运行状态
        if self.done % 20 == 0:
            with open(os.path.join(self.config.out_dir, f".{self.taskid}"), 'w') as f:
                f.write(f"{str(self.done)},{str(self.found)},{self.runned_time + timer.get_time_stamp() - self.create_time}")

    def __del__(self):
        try:  # if dont use try, sys.exit() may cause error
            self.record_running_state()
            self.vulnerable.close()
            self.not_vulneralbe.close()
        except Exception as e:
            logger.error(e)


@common.singleton
class SnapshotPipeline:

    def __init__(self, config):
        self.config = config
        self.var_lock = RLock()
        self.pipeline = Queue(self.config.th_num * 2)
        self.workers = ThreadPoolExecutor(self.config.th_num)
        self.snapshots_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        self.done = len(os.listdir(self.snapshots_dir))
        self.task_count = 0
        self.task_count_lock = Lock()

    def put(self, msg):
        """放入一条消息
        Queue 自代锁，且会阻塞
        params:
        - msg: (poc.exploit, results)
        """
        self.pipeline.put(msg)

    def empty(self):
        return self.pipeline.empty()

    def get(self):
        return self.pipeline.get()

    def get_done(self):
        with self.var_lock:
            return self.done

    def add_done(self, num=1):
        with self.var_lock:
            self.done += num

    def _snapshot(self, exploit_func, results):
        """利用 poc 的 exploit 方法获取 results 处的资源
        params:
        - exploit_func: pocs 路径下每个 poc 的 exploit 方法
        - results: poc 的 verify 验证为真时的返回结果
        """
        if res := exploit_func(results):
            self.add_done(res)
        with self.task_count_lock:
            self.task_count -= 1

    def process(self, core):
        while not core.finish():
            exploit_func, results = self.get()
            self.workers.submit(self._snapshot, exploit_func, results)
            with self.task_count_lock:
                self.task_count += 1
            time.sleep(.1)