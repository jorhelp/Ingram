import os
import requests
from collections import namedtuple

from loguru import logger


class POCTemplate:

    level = namedtuple('level', 'high medium low')('高', '中', '低')
    poc_classes = []

    @staticmethod
    def register_poc(self):
        self.poc_classes.append(self)

    def __init__(self, config):
        self.config = config
        # poc 名称 (直接用文件名或者另取一个名字)
        self.name = self.get_file_name(__file__)
        # poc 所针对的应用
        self.product = 'base'
        # 应用版本
        self.product_version = ''
        # 引用的 url
        self.ref = ''
        # 漏洞等级
        self.level = self.level.low
        # 描述
        self.desc = """"""

    def get_file_name(self, file):
        return os.path.basename(file).split('.')[0]

    def verify(self, ip, port):
        """用来验证是否存在该漏洞
        params:
        - ip: ip 地址, str
        - port: 端口号, str or num 

        return:
        - 验证成功的形式为 (ip, port, self.product, user, password, self.name)
        - 验证失败的形式为 None
        """
        pass

    def _snapshot(self, url, img_file_name, auth=None) -> int:
        """下载 url 处的图片并保存到 file_name
        通过设置 stream=True 来友好地下载较大的媒体文件
        """
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        try:
            if auth:
                res = requests.get(url, auth=auth, timeout=self.config.timeout, verify=False, headers=headers, stream=True)
            else:
                res = requests.get(url, timeout=self.config.timeout, verify=False, headers=headers, stream=True)
            if res.status_code == 200:
                with open(img_path, 'wb') as f:
                    # 每次写入 10 KB
                    for content in res.iter_content(10240):
                        f.write(content)
                return 1
        except Exception as e:
            logger.error(e)
        return 0

    def exploit(self, results: tuple) -> int:
        """利用, 主要是获取 snapshot
        params:
        - results: self.verify 验证成功时的返回结果
        return:
        - 返回一个数, 代表获取了几张截图, 一般为 1 或 0
        """
        url = ''
        img_file_name = ''
        return self._snapshot(url, img_file_name)