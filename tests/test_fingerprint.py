"""Test per Ingram.utils.fingerprint._parse (funzione pura, senza rete)."""
import hashlib
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram.utils.fingerprint import _parse


class FakeResp:
    def __init__(self, text='', headers=None, status_code=200, content=b''):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.content = content or text.encode('utf-8', 'ignore')


def test_title_match():
    r = FakeResp(text="<html><head><title>Hikvision Login</title></head><body></body></html>")
    assert _parse(r, "title=`hikvision`") is True
    assert _parse(r, "title=`nonesistente`") is False


def test_missing_title_no_crash():
    # Prima sollevava IndexError; ora deve restituire False senza eccezioni
    r = FakeResp(text="<html><body>no title here</body></html>")
    assert _parse(r, "title=`whatever`") is False


def test_missing_body_no_crash():
    r = FakeResp(text="<html><head><title>x</title></head></html>")
    assert _parse(r, "body=`whatever`") is False


def test_body_match():
    r = FakeResp(text="<html><body><div>doc/page/login.asp</div></body></html>")
    assert _parse(r, "body=`doc/page/login.asp`") is True


def test_headers_match():
    r = FakeResp(headers={'Server': 'Hikvision-Webs'})
    assert _parse(r, "headers=`hikvision-webs`") is True
    assert _parse(r, "headers=`apache`") is False


def test_status_code():
    r = FakeResp(status_code=401)
    assert _parse(r, "status_code=`401`") is True
    assert _parse(r, "status_code=`200`") is False


def test_md5():
    content = b"favicon-bytes"
    r = FakeResp(content=content)
    digest = hashlib.md5(content).hexdigest()
    assert _parse(r, f"md5=`{digest}`") is True


def test_and_condition():
    r = FakeResp(text="<html><head><title>x</title></head><body><div>g_szCacheTime</div><span>iVMS</span></body></html>")
    assert _parse(r, "body=`g_szCacheTime`&&body=`iVMS`") is True
    assert _parse(r, "body=`g_szCacheTime`&&body=`assente`") is False


def test_malformed_rule_no_crash():
    r = FakeResp(text="<html></html>")
    assert _parse(r, "garbage-without-backtick") is False


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    passed = 0
    for fn in fns:
        fn(); passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} passed")


# --- HTTPS fallback + retry (con Session finta, senza rete) -----------------
from collections import namedtuple
import requests as _requests

Rule = namedtuple('Rule', ['product', 'path', 'val'])


class _Cfg:
    """config minimale per fingerprint()"""
    def __init__(self, rules, retries=0, retry_delay=0.0):
        self.rules = rules
        self.user_agent = 'ua'
        self.timeout = 1
        self.retries = retries
        self.retry_delay = retry_delay


class _FakeResp:
    def __init__(self, text='', headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.content = text.encode('utf-8', 'ignore')


class _FakeSession:
    """restituisce risposte in base allo schema dell'URL; registra le chiamate"""
    def __init__(self, http_exc=None, https_resp=None, http_resp=None):
        self.http_exc = http_exc
        self.https_resp = https_resp
        self.http_resp = http_resp
        self.calls = []
        self.closed = False

    def get(self, url, **kw):
        self.calls.append(url)
        if url.startswith('http://'):
            if self.http_exc is not None:
                raise self.http_exc
            return self.http_resp
        return self.https_resp

    def close(self):
        self.closed = True


def test_fingerprint_http_success():
    from Ingram.utils.fingerprint import fingerprint
    rules = {Rule('hikvision', '/', 'title=`hikvision`')}
    resp = _FakeResp(text='<html><head><title>Hikvision</title></head></html>')
    sess = _FakeSession(http_resp=resp)
    assert fingerprint('1.1.1.1', 80, _Cfg(rules), session=sess) == 'hikvision'
    assert all(u.startswith('http://') for u in sess.calls)   # nessun https se http basta
    assert sess.closed is False                                # session iniettata non chiusa


def test_fingerprint_falls_back_to_https():
    from Ingram.utils.fingerprint import fingerprint
    rules = {Rule('axis', '/', 'title=`axis`')}
    resp = _FakeResp(text='<html><head><title>AXIS Camera</title></head></html>')
    sess = _FakeSession(http_exc=_requests.exceptions.ConnectionError('refused'),
                        https_resp=resp)
    assert fingerprint('2.2.2.2', 443, _Cfg(rules), session=sess) == 'axis'
    assert any(u.startswith('http://') for u in sess.calls)
    assert any(u.startswith('https://') for u in sess.calls)  # fallback avvenuto


def test_fingerprint_retries_then_gives_up():
    from Ingram.utils.fingerprint import fingerprint
    rules = {Rule('x', '/', 'title=`x`')}
    # sia http che https falliscono; retries=1 => 2 tentativi per schema
    sess = _FakeSession(http_exc=_requests.exceptions.ConnectionError('down'),
                        https_resp=None)

    def _get(url, **kw):
        sess.calls.append(url)
        raise _requests.exceptions.ConnectionError('down')
    sess.get = _get
    cfg = _Cfg(rules, retries=1, retry_delay=0.0)
    assert fingerprint('3.3.3.3', 80, cfg, session=sess) is None
    # 2 tentativi http + 2 tentativi https = 4
    assert len(sess.calls) == 4


def test_rules_csv_well_formed():
    """ogni riga di rules.csv deve avere esattamente 3 campi (product,path,val);
    la val non deve contenere virgole non citate che romperebbero il parsing."""
    import os
    rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'Ingram', 'rules.csv')
    with open(rules_path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split(',', 2)
            assert len(parts) == 3, f"rules.csv riga {i} malformata: {line!r}"
            product, path, val = parts
            assert product and path.startswith('/') and val, \
                f"rules.csv riga {i} campi vuoti/invalidi: {line!r}"


def test_new_rules_present():
    """le nuove firme ad alta confidenza devono essere caricate"""
    import os
    rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'Ingram', 'rules.csv')
    body = open(rules_path).read()
    assert 'uc-httpd' in body          # xiongmai/sofia
    assert 'vvtk' in body              # vivotek
    assert 'MOBOTIX' in body          # mobotix
