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
