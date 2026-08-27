import glob
import importlib
import os
from collections import defaultdict

from loguru import logger

from .base import POCTemplate


# 单个 POC 模块导入失败不应影响其余 POC (以及整个工具) 的加载
load_errors = []
for _path in sorted(glob.glob(os.path.join(os.path.dirname(__file__), '*.py'))):
    _file_name = os.path.basename(_path)[:-3]
    if _file_name in ('__init__', 'base'):
        continue
    try:
        importlib.import_module(f".{_file_name}", 'Ingram.pocs')
    except Exception as e:
        load_errors.append((_file_name, e))
        logger.warning(f"skip POC '{_file_name}': {e}")


def get_poc_dict(config):
    """构建 product -> [poc, ...] 的映射

    支持通过 config.poc / config.exclude_poc 选择要运行的 POC,
    匹配 POC 文件名 (poc.name) 或其针对的产品 (poc.product)。
    """
    include = set(getattr(config, 'poc', None) or [])
    exclude = set(getattr(config, 'exclude_poc', None) or [])

    poc_dict = defaultdict(list)
    for POC in POCTemplate.poc_classes:
        try:
            poc = POC(config)
        except Exception as e:
            logger.warning(f"skip POC '{getattr(POC, '__name__', POC)}': {e}")
            continue
        if include and (poc.name not in include) and (poc.product not in include):
            continue
        if (poc.name in exclude) or (poc.product in exclude):
            continue
        poc_dict[poc.product].append(poc)
    return poc_dict
