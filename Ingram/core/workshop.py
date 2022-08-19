"""the workshop that load data and produce product"""
import os
from queue import Queue
from threading import RLock
from concurrent.futures import ThreadPoolExecutor

from Ingram.middleware import snapshot


class Workshop:

    def __init__(self, output, th_num=8):
        self.output = output
        self.var_lock = RLock()
        self.pipeline = Queue(th_num * 2)
        self.workers = ThreadPoolExecutor(th_num)
        self.done = 0

        self.preprocess()

    def preprocess(self):
        if os.path.exists(self.output):
            self.done = len(os.listdir(self.output))
        else:
            os.mkdir(self.output)

    def put(self, msg):
        # Queue 自带锁, 且会阻塞
        self.pipeline.put(msg)

    def empty(self):
        return self.pipeline.empty()

    def get(self):
        # Queue 自带锁, 且会阻塞
        return self.pipeline.get()

    def get_done(self):
        with self.var_lock:
            return self.done

    def done_add(self):
        with self.var_lock:
            self.done += 1

    def process(self):
        while not self.empty():
            item = self.get()
            self.workers.submit(snapshot, item, self)