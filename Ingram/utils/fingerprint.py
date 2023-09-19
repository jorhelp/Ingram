"""根据指纹给出目标产品信息"""
import hashlib
import re
import requests

from loguru import logger
from lxml import etree


def _parse(req, rule_val):
    """判断 requests 返回值是否符合指纹规则
    rule_val 可能是多种规则的且关系: xxx&&xxx...
    """
    def check_one(item):
        left, right = re.search(r'(.*)=`(.*)`', item).groups()

        if left == 'md5':
            if hashlib.md5(req.content).hexdigest() == right:
                return True
        elif left == 'title':
            html = etree.HTML(req.text)
            if right.lower() in html.xpath('//title')[0].xpath('string(.)').lower():
                return True
        elif left == 'body':
            html = etree.HTML(req.text)
            for node in html.xpath('//body')[0]:
                if right.lower() in node.xpath('string(.)').lower():
                    return True
        elif left == 'headers':
            for header_item in req.headers.items():
                if right.lower() in ''.join(header_item).lower():
                    return True
        elif left == 'status_code':
            return int(req.status_code) == int(right)
        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    req_dict = {}  # 暂存 requests 的返回值
    session = requests.session()
    headers = {'Connection': 'close', 'User-Agent': config.user_agent}
    for rule in config.rules:
        try:
            req = req_dict.get(rule.path) or session.get(f"http://{ip}:{port}{rule.path}", headers=headers, timeout=config.timeout)
            # req_dict 里只保存 status_code 为 200 的 req
            if (rule.path not in req_dict) and (req.status_code == 200):
                req_dict[rule.path] = req
            # 不同处理方式
            if _parse(req, rule.val):
                return rule.product
        except Exception as e:
            logger.error(e)
    return None