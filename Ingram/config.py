"""全局配置项"""
import os
from collections import namedtuple

from loguru import logger

from .utils import net


_config = {
    'users': ['admin'],
    'passwords': [
        'admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc',
        '', '12345', '123456', 'password', '888888', '666666', 'system', 'admin123',
    ],
    'user_agent': net.get_user_agent(),  # to save time, we only get user agent once.
    'ports': [80, 81, 82, 83, 84, 85, 88, 8000, 8001, 8080, 8081, 8085, 8086, 8088, 8090, 8181, 2051, 9000, 37777, 49152, 55555],

    # rules
    'product': {},
    'rules': set(),

    # runtime flags
    'no_resume': False,
    'format': 'csv',       # 输出格式: csv | json | both
    'poc': None,           # 仅运行这些 POC (按文件名或产品名); None 表示全部
    'exclude_poc': None,   # 排除这些 POC (按文件名或产品名)

    # file & dir
    'log': 'log.txt',
    'not_vulnerable': 'not_vulnerable.csv',
    'vulnerable': 'results.csv',
    'not_vulnerable_json': 'not_vulnerable.json',
    'vulnerable_json': 'results.json',
    'snapshots': 'snapshots',

    # wechat
    'wxuid': '',
    'wxtoken': '',
}

# 这些命令行参数只用于加载凭据文件, 不应直接进入最终配置
_CREDENTIAL_FILE_ARGS = ('users_file', 'pass_file')


def _load_list_file(path):
    """从文件读取一个列表, 每行一个条目, 忽略空行和以 # 开头的注释行"""
    items = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                items.append(line)
    return items


def get_config(args=None):
    # 指纹规则
    Rule = namedtuple('Rule', ['product', 'path', 'val'])
    with open(os.path.join(os.path.dirname(__file__), 'rules.csv'), 'r') as f:
        for line in [l.strip() for l in f if l.strip()]:
            product, path, val = line.split(',')
            _config['rules'].add(Rule(product, path, val))
            _config['product'][product] = product

    # 组装命令行获取的参数值
    if args:
        args = vars(args)

        # 先处理凭据文件 (会被随后的显式 -u/--passwords 列表覆盖)
        if args.get('users_file'):
            _config['users'] = _load_list_file(args['users_file'])
            logger.info(f"loaded {len(_config['users'])} users from {args['users_file']}")
        if args.get('pass_file'):
            _config['passwords'] = _load_list_file(args['pass_file'])
            logger.info(f"loaded {len(_config['passwords'])} passwords from {args['pass_file']}")

        for arg, value in args.items():
            if arg in _CREDENTIAL_FILE_ARGS:
                continue
            # 此处不要直接 if value，因为这样会导致空字符串也为 False
            if value is not None:
                _config[arg] = value

    Config = namedtuple('config', _config.keys())
    return Config(**_config)
