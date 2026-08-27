import json
import os
from collections import defaultdict
from threading import Thread

import gevent
from loguru import logger
from gevent.pool import Pool as geventPool

from .data import Data, SnapshotPipeline, VULN_FIELDS
from .pocs import get_poc_dict
from .utils import color
from .utils import common
from .utils import fingerprint
from .utils import port_scan
from .utils import status_bar
from .utils import timer
from .utils.throttle import RateLimiter


def _read_csv_rows(csv_file):
    rows = []
    with open(csv_file, 'r') as f:
        for line in f:
            if (line := line.strip()):
                parts = line.split(',')
                if len(parts) >= 3:
                    rows.append((parts[2], parts[-1]))
    return rows


def _read_json_rows(json_file):
    rows = []
    with open(json_file, 'r') as f:
        for line in f:
            if (line := line.strip()):
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                rows.append((rec.get('product', ''), rec.get('poc', '')))
    return rows


def _read_csv_full(csv_file):
    """按 VULN_FIELDS 的列顺序把 results.csv 读成 dict 列表"""
    rows = []
    with open(csv_file, 'r') as f:
        for line in f:
            if (line := line.strip()):
                parts = line.split(',')
                if len(parts) >= 3:
                    rows.append({k: (parts[i] if i < len(parts) else '')
                                 for i, k in enumerate(VULN_FIELDS)})
    return rows


def _read_json_full(json_file):
    rows = []
    with open(json_file, 'r') as f:
        for line in f:
            if (line := line.strip()):
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                rows.append({k: rec.get(k, '') for k in VULN_FIELDS})
    return rows


def read_full_result_rows(csv_file, json_file, fmt='csv'):
    """与 read_result_rows 相同的数据源选择逻辑, 但返回完整字段的 dict 列表
    (供 HTML 报告使用)。"""
    if fmt == 'json':
        return _read_json_full(json_file) if os.path.exists(json_file) else []
    if os.path.exists(csv_file):
        return _read_csv_full(csv_file)
    if os.path.exists(json_file):
        return _read_json_full(json_file)
    return []


LEVEL_LABEL = {'高': 'HIGH', '中': 'MEDIUM', '低': 'LOW'}


def build_findings(vuln_names, poc_meta):
    """A partire dai nomi dei POC trovati e da una mappa nome -> (level, desc),
    produce una lista ordinata e deduplicata di (severità, nome, descrizione)
    per la sezione FINDINGS del report."""
    seen = set()
    details = []
    for vul_name in vuln_names:
        if vul_name in seen:
            continue
        seen.add(vul_name)
        level, desc = poc_meta.get(vul_name, ('', ''))
        desc = ' '.join((desc or '').split())
        if len(desc) > 200:
            desc = desc[:197] + '...'
        details.append((LEVEL_LABEL.get(level, level or '?'), vul_name, desc))
    return details


def read_result_rows(csv_file, json_file, fmt='csv'):
    """读取漏洞结果, 返回 (product, poc) 列表

    按本次运行的输出格式选择数据源, 而不是看磁盘上哪个文件存在:
    这样在同一 out_dir 上切换 -f 时, 不会误读上一次运行遗留的 results.csv。
    """
    if fmt == 'json':
        return _read_json_rows(json_file) if os.path.exists(json_file) else []
    # csv / both: 本次会写 results.csv, 优先读它; 缺失时回退到 json
    if os.path.exists(csv_file):
        return _read_csv_rows(csv_file)
    if os.path.exists(json_file):
        return _read_json_rows(json_file)
    return []


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
        fmt = getattr(self.config, 'format', 'csv')
        csv_path = os.path.join(self.config.out_dir, self.config.vulnerable)
        json_path = os.path.join(self.config.out_dir, self.config.vulnerable_json)
        items = read_result_rows(csv_path, json_path, fmt)

        # mappa nome_poc -> (severità, descrizione) per arricchire il report
        poc_meta = {}
        for pocs in self.poc_dict.values():
            for poc in pocs:
                poc_meta[poc.name] = (getattr(poc, 'level', ''), getattr(poc, 'desc', '') or '')

        # report HTML opzionale (scritto anche quando non ci sono findings)
        if getattr(self.config, 'report_html', False):
            self._write_html_report(csv_path, json_path, fmt, poc_meta)

        if not items:
            return

        results = defaultdict(lambda: defaultdict(lambda: 0))
        for product, vul in items:
            dev = product.split('-')[0]
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

        # dettaglio per falla: severità + cosa consente (dai campi level/desc dei POC)
        vuln_names = [vul_name for dev in results for vul_name in results[dev]]
        details = build_findings(vuln_names, poc_meta)
        if details:
            print('\n')
            print('-' * 18, 'FINDINGS', '-' * 18)
            for label, vul_name, desc in details:
                print(color.red(f"[{label}] {vul_name}", 'bright'))
                if desc:
                    print(color.white(f"    {desc}"))
            print('-' * 46)
        print('\n')

    def _write_html_report(self, csv_path, json_path, fmt, poc_meta):
        """genera e salva il report HTML nella out_dir"""
        from .utils.report_html import build_html_report
        rows = read_full_result_rows(csv_path, json_path, fmt)
        findings = build_findings([r.get('poc', '') for r in rows], poc_meta)
        meta = {
            'generated': timer.get_time_formatted(),
            'total': self.data.total,
            'done': self.data.done,
            'found': self.data.found,
        }
        html = build_html_report(rows, findings, meta)
        out_path = os.path.join(self.config.out_dir, self.config.report_html_file)
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html)
            logger.info(f"html report saved to {out_path}")
        except Exception as e:
            logger.error(f"failed to write html report: {e}")

    def _scan_port(self, ip, port):
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

    def _scan(self, target):
        """
        params:
        - target: 有两种形式, 即 ip 或 ip:port
        """
        items = target.split(':')
        ip = items[0]
        ports = [items[1], ] if len(items) > 1 else self.config.ports

        # 端口并发扫描
        jobs = [gevent.spawn(self._scan_port, ip, port) for port in ports]
        gevent.joinall(jobs)

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
            # 使用 pool.spawn 而非 start(gevent.spawn(...)): 前者先获取池信号量再创建协程,
            # 从而把并发严格约束在 th_num; 旧写法会先 spawn 协程再获取信号量, 可能短暂超出上限
            scan_pool = geventPool(self.config.th_num)
            # 限速: 约束新主机的启动速率 (0 = 不限速); 在主协程里 gate,
            # 因为生成/派发循环本身是单协程, 无需加锁
            rate_limiter = RateLimiter(getattr(self.config, 'rate', 0.0))
            for ip in self.data.ip_generator:
                wait = rate_limiter.acquire()
                if wait > 0:
                    gevent.sleep(wait)
                scan_pool.spawn(self._scan, ip)
            scan_pool.join()

            # self.snapshot_pipeline_thread.join()
            self.status_bar_thread.join()

            self.report()

        except KeyboardInterrupt:
            pass

        except Exception as e:
            logger.error(e)