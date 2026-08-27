"""根据指纹给出目标产品信息"""
import hashlib
import re

import gevent
import requests
from loguru import logger
from lxml import etree

from .throttle import retry


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


def fingerprint(ip, port, config, session=None):
    """对 ip:port 做指纹识别, 命中则返回产品名, 否则返回 None。

    - 先尝试 http, 连接失败再回退到 https (很多摄像头只开 https),
      成功后记住可用的 scheme, 避免对每条规则都重复探测两个 scheme。
    - 每个 HTTP 请求按 config.retries/config.retry_delay 做重试 (仅网络异常)。
    - session 可注入 (便于测试); 内部创建时负责关闭。
    """
    own_session = session is None
    if own_session:
        session = requests.Session()

    headers = {'Connection': 'close', 'User-Agent': config.user_agent}
    retries = getattr(config, 'retries', 0)
    retry_delay = getattr(config, 'retry_delay', 0.0)
    state = {'scheme': None}      # 记住第一个成功响应的 scheme
    req_dict = {}                 # 暂存 status_code 为 200 的 req

    def _do_get(url):
        return session.get(url, headers=headers, timeout=config.timeout, verify=False)

    def _get(path):
        # 已知可用 scheme 时只用它; 否则依次尝试 http -> https
        candidates = [state['scheme']] if state['scheme'] else ['http', 'https']
        last_exc = None
        for scheme in candidates:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                resp = retry(
                    lambda: _do_get(url),
                    attempts=retries + 1,
                    delay=retry_delay,
                    exceptions=(requests.exceptions.RequestException,),
                    sleeper=gevent.sleep,
                )
                state['scheme'] = scheme
                return resp
            except requests.exceptions.RequestException as e:
                last_exc = e
                continue
        raise last_exc

    try:
        for rule in config.rules:
            try:
                req = req_dict.get(rule.path)
                if req is None:
                    req = _get(rule.path)
                    # req_dict 里只保存 status_code 为 200 的 req
                    if req.status_code == 200:
                        req_dict[rule.path] = req
                if _parse(req, rule.val):
                    return rule.product
            except Exception as e:
                logger.debug(f"fingerprint {ip}:{port}{rule.path}: {e}")
    finally:
        if own_session:
            session.close()
    return None
