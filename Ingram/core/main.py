"""coordinate various configurations and make decisions"""
import os
import time
from threading import Thread
from collections import defaultdict

import gevent
from gevent.pool import Pool as geventPool

from Ingram.utils import config
from Ingram.utils import logger
from Ingram.utils import color
from Ingram.utils import singleton
from Ingram.utils import get_current_time
from Ingram.core.scan import Scan
from Ingram.core.data import Data
from Ingram.core.workshop import Workshop
from Ingram.middleware import status_bar


def consumer(core):
    try:
        while not core.finish:
            core.workshop.process()
            time.sleep(.1)
    except KeyboardInterrupt as e:
        # os._exit(0)  # 这种退出方式常用在子进程中
        exit(0)
    except Exception as e:
        logger.error(e)
        exit(0)


def status(core):
    bar = status_bar()
    tmp = 0
    try:
        while True:
            if tmp % 15 == 0:  # every ~1s
                time_interval = get_current_time() - core.data.create_time + core.data.runned_time
                core.data.record_running_state()
            total = core.data.get_total()
            done = core.data.get_done()
            found = core.data.get_found()
            product = core.workshop.get_done()
            bar(total, done, found, product, time_interval)
            time.sleep(.05)
            tmp = tmp + 1 if tmp < 100 else 0
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        logger.error(e)
        exit(0)


@singleton
class Core:

    def __init__(self):
        self.finish = False
        self.data = Data(config.IN, config.OUT)
        self.workshop = Workshop(os.path.join(config.OUT, 'snapshots'), config.TH // 4)
        self.scan = Scan(self.data, self.workshop, config.PORT)
        self.scan_pool = geventPool(config.TH)

        self.status = Thread(target=status, args=(self, ))
        self.consumer = Thread(target=consumer, args=(self, ))
        self.get_data_from_disk = Thread(target=self.data.get_data_from_disk)

    def __call__(self):
        try:
            # logger config vars
            logger.info(config.__dict__)

            self.status.setDaemon(True)
            self.status.start()
            self.get_data_from_disk.start()
            self.consumer.start()
            for ip in self.data.ip_generator:
                self.scan_pool.start(gevent.spawn(self.scan, ip))
            self.scan_pool.join()

            time.sleep(.1)  # the last item may not print
            self.finish = True  # terminate the status thread
            self.data.record_running_state()

            self.report()
            self.consumer.join()
            self.get_data_from_disk.join()

        except KeyboardInterrupt as e:
            self.finish = True
            exit(0)

        except Exception as e:
            self.finish = True
            logger.error(e)
            exit(0)

    def __del__(self):
        try:
            self.scan_pool.kill()
        except Exception as e:
            logger.error(e)

    def report(self):
        """report the results"""
        results_file = os.path.join(config.OUT, 'results.csv')
        if os.path.exists(results_file):
            with open(results_file, 'r') as f:
                items = [l.strip().split(',') for l in f if l.strip()]

            if items:
                results = defaultdict(lambda: defaultdict(lambda: 0))
                for i in items:
                    dev, vul = i[2].split('-')[0], i[-1]
                    results[dev][vul] += 1
                results_sum = len(items)
                results_max = max([val for vul in results.values() for val in vul.values()])
                
                print('\n')
                print('-' * 19, 'REPORT', '-' * 19)
                for dev in results:
                    vuls = [(vul_name, vul_count) for vul_name, vul_count in results[dev].items()]
                    dev_sum = sum([i[1] for i in vuls])
                    print(color.red(f"{dev} {dev_sum}", 'bright'))
                    for vul_name, vul_count in vuls:
                        block_num = int(vul_count / results_max * 25)
                        print(color.green(f"{vul_name:>18} | {'▥' * block_num} {vul_count}"))
                print(color.yellow(f"{'sum: ' + str(results_sum):>46}", 'bright'), flush=True)
                print('-' * 46)
                print('\n')
