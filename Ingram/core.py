import os
from collections import defaultdict
from threading import Thread

import gevent
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline
from .pocs import get_poc_dict
from .utils import color
from .utils import common
from .utils import fingerprint
from .utils import port_scan
from .utils import status_bar
from .utils import timer


@common.singleton
class Core:

    def __init__(self, config):
        self.config = config
        self.data = Data(config)
        self.snapshot_pipeline = SnapshotPipeline(config)
        self.poc_dict = get_poc_dict(self.config)

    def finish(self):
        return (self.data.done >= self.data.total) and (self.snapshot_pipeline.task_count <= 0)

    def report(self):
        """report the results"""
        results_file = os.path.join(self.config.out_dir, self.config.vulnerable)
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

    def _scan(self, target):
        """
        params:
        - target: 有两种形式, 即 ip 或 ip:port
        """
        items = target.split(':')
        ip = items[0]
        ports = [items[1], ] if len(items) > 1 else self.config.ports

        # 存活检测 (是否有必要)

        # 端口扫描
        for port in ports:
            if port_scan(ip, port, self.config.timeout):
                logger.info(f"{ip} port {port} is open")
                # 指纹
                if product := fingerprint(ip, port, self.config):
                    logger.info(f"{ip}:{port} is {product}")
                    verified = False
                    # poc verify & exploit
                    for poc in self.poc_dict[product]:
                        if results := poc.verify(ip, port):
                            verified = True
                            # found 加 1
                            self.data.add_found()
                            # 将验证成功的 poc 记录到 config.vulnerable 中
                            self.data.add_vulnerable(results[:6])
                            # snapshot
                            if not self.config.disable_snapshot:
                                self.snapshot_pipeline.put((poc.exploit, results))
                    if not verified:
                        self.data.add_not_vulnerable([ip, str(port), product])
        self.data.add_done()
        self.data.record_running_state()

    def run(self):
        logger.info(f"running at {timer.get_time_formatted()}")
        logger.info(f"config is {self.config}")

        try:
            # 状态栏
            self.status_bar_thread = Thread(target=status_bar, args=[self, ], daemon=True)
            self.status_bar_thread.start()
            # snapshot
            if not self.config.disable_snapshot:
                self.snapshot_pipeline_thread = Thread(target=self.snapshot_pipeline.process, args=[self, ], daemon=True)
                self.snapshot_pipeline_thread.start()
            # 扫描
            # with common.IngramThreadPool(self.config.th_num) as pool:
            #     pool.map(self._scan, self.data.ip_generator)
            scan_pool = geventPool(self.config.th_num)
            for ip in self.data.ip_generator:
                scan_pool.start(gevent.spawn(self._scan, ip))
            scan_pool.join()

            # self.snapshot_pipeline_thread.join()
            self.status_bar_thread.join()

            self.report()

        except KeyboardInterrupt:
            pass

        except Exception as e:
            logger.error(e)