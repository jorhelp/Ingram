"""coordinate various configurations and make decisions"""
import os
import time
from functools import partial
from multiprocessing import Process
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor

from gevent import monkey; monkey.patch_all(thread=False)
from gevent.pool import Pool as geventPool

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import singleton
from Ingram.utils import get_all_ip
from Ingram.core.scan import Scan
from Ingram.core.data import Data
from Ingram.middleware import snapshot


def consumer(msg_queue, path, maxtry, timeout):
    _snapshot = partial(snapshot, path=path, maxtry=maxtry, timeout=timeout)
    pool = ThreadPoolExecutor(8)
    while True:
        try:
            if msg_queue.empty():
                time.sleep(.1)
            else:
                item = msg_queue.get()
                if item == 'done':
                    return
                # multithread
                pool.submit(_snapshot, item)
        except KeyboardInterrupt as e:
            os._exit(0)  # 这种退出方式常用在子进程中
        except Exception as e:
            os._exit(0)


@singleton
class Core:

    def __init__(self):
        self.data = Data(config['IN'], config['OUT'])
        self.scan = Scan(self.data, config['PORT'])
        self.consumer = Process(target=consumer,
                                args=(self.data.msg_queue,
                                      os.path.join(config['OUT'], 'snapshot'),
                                      config['MAXTRY'],
                                      config['TIMEOUT']))

        # logger config vars
        logger.info(config.config_dict.items())

    def __call__(self):
        try:
            self.consumer.start()
            # gevent pool
            with self.data.var_lock:
                self.scan.bar(self.data.done, self.data.found)
            self.scan_pool = geventPool(config['TH'])
            self.scan_pool.map_async(self.scan, self.data.ip_generator).get()

            # # threading pool
            # with ThreadPool(config['TH']) as pool:
            #     pool.map_async(self.scan, self.data.ip_generator).get()

            self.data.msg_queue.put('done')
            self.consumer.join()
            # self.report()
            logger.info('Ingram done')
            self.consumer.terminate()
        except Exception as e:
            logger.error(e)
            exit(0)

    def __del__(self):
        try:
            self.scan_pool.kill()
            self.consumer.terminate()
            del self.data
            del self.scan
            del self.consumer
        except Exception as e:
            logger.error(e)

    # def report(self):
    #     """report the results"""
    #     if not os.path.exists(os.path.join(self.args.out_path, RESULTS_ALL)):
    #         return

    #     with open(os.path.join(self.args.out_path, RESULTS_ALL), 'r') as f:
    #         items = [l.strip().split(',') for l in f if l.strip()]

    #     results = defaultdict(lambda: defaultdict(lambda: 0))
    #     for i in items:
    #         dev, vul = i[-2].split('-')[0], i[-1]
    #         results[dev][vul] += 1
    #     results_sum = len(items)
    #     results_max = max([val for vul in results.values() for val in vul.values()])
        
    #     print('\n')
    #     print('-' * 19, 'REPORT', '-' * 19)
    #     for dev in results:
    #         vuls = [(vul_name, vul_count) for vul_name, vul_count in results[dev].items()]
    #         dev_sum = sum([i[1] for i in vuls])
    #         printf(f"{dev} {dev_sum}", color='red', bold=True)
    #         for vul_name, vul_count in vuls:
    #             printf(f"{vul_name:>18} | ", end='')
    #             block_num = int(vul_count / results_max * 25)
    #             printf('▥' * block_num, end=' ')
    #             printf(vul_count)
    #     printf(f"{'sum: ' + str(results_sum):>46}", color='yellow', flash=True)
    #     print('-' * 46)
    #     print('\n')
