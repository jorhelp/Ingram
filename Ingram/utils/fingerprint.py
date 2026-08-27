"""根据指纹给出目标产品信息"""
import hashlib
import re

import requests
from loguru import logger
from lxml import etree


# 预编译正则, 避免每次匹配都重新编译
_RULE_RE = re.compile(r'(.*)=`(.*)`')


def _get_html(req):
    """解析并缓存一次 HTML 树, 避免对同一响应重复解析"""
    if not hasattr(req, '_ingram_html'):
        try:
            req._ingram_html = etree.HTML(req.text)
        except Exception:
            req._ingram_html = None
    return req._ingram_html


def _parse(req, rule_val):
    """判断 requests 返回值是否符合指纹规则
    rule_val 可能是多种规则的且关系: xxx&&xxx...
    """
    def check_one(item):
        m = _RULE_RE.search(item)
        if not m:
            return False
        left, right = m.groups()

        if left == 'md5':
            return hashlib.md5(req.content).hexdigest() == right
        elif left == 'title':
            html = _get_html(req)
            if html is None:
                return False
            titles = html.xpath('//title')
            if not titles:
                return False
            return right.lower() in titles[0].xpath('string(.)').lower()
        elif left == 'body':
            html = _get_html(req)
            if html is None:
                return False
            bodies = html.xpath('//body')
            if not bodies:
                return False
            for node in bodies[0]:
                if right.lower() in node.xpath('string(.)').lower():
                    return True
            return False
        elif left == 'headers':
            for header_item in req.headers.items():
                if right.lower() in ''.join(header_item).lower():
                    return True
            return False
        elif left == 'status_code':
            return int(req.status_code) == int(right)
        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    req_dict = {}  # 暂存 requests 的返回值
    headers = {'Connection': 'close', 'User-Agent': config.user_agent}
    with requests.Session() as session:
        for rule in config.rules:
            try:
                req = req_dict.get(rule.path) or session.get(
                    f"http://{ip}:{port}{rule.path}", headers=headers, timeout=config.timeout)
                # req_dict 里只保存 status_code 为 200 的 req
                if (rule.path not in req_dict) and (req.status_code == 200):
                    req_dict[rule.path] = req
                # 不同处理方式
                if _parse(req, rule.val):
                    return rule.product
            except Exception as e:
                logger.debug(f"fingerprint {ip}:{port}{rule.path}: {e}")
    return None
