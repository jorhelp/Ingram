"""Test funzioni pure di Ingram.utils.net (parsing/espansione IP)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram.utils import net


def test_single_ip():
    assert net.get_ip_seg_len('192.168.0.1') == 1
    assert list(net.get_all_ip('192.168.0.1')) == ['192.168.0.1']


def test_cidr_len_and_expand():
    assert net.get_ip_seg_len('192.168.0.0/30') == 4
    ips = list(net.get_all_ip('192.168.0.0/30'))
    assert len(ips) == 4
    assert ips[0] == '192.168.0.0' and ips[-1] == '192.168.0.3'


def test_range_len_and_expand():
    assert net.get_ip_seg_len('10.0.0.1-10.0.0.4') == 4
    ips = list(net.get_all_ip('10.0.0.1-10.0.0.4'))
    assert len(ips) == 4
    assert '10.0.0.1' in ips and '10.0.0.4' in ips


def test_non_boundary_range():
    """Regressione: prima IPy.IP(range, make_net=True) sollevava ValueError
    per range non allineati a un confine di rete."""
    seg = '172.16.0.0-172.16.0.10'
    assert net.get_ip_seg_len(seg) == 11
    ips = list(net.get_all_ip(seg))
    assert len(ips) == 11
    assert ips[0] == '172.16.0.0' and ips[-1] == '172.16.0.10'


def test_reversed_range():
    seg = '10.0.0.10-10.0.0.8'
    assert net.get_ip_seg_len(seg) == 3
    assert list(net.get_all_ip(seg)) == ['10.0.0.8', '10.0.0.9', '10.0.0.10']


def test_len_matches_expand():
    """la lunghezza dichiarata deve coincidere col numero di IP generati
    (invariante su cui si basa la ripresa da stato)."""
    for seg in ['192.168.1.0/29', '172.16.0.0-172.16.0.10', '10.0.0.1-10.0.0.4', '8.8.8.8']:
        assert net.get_ip_seg_len(seg) == len(list(net.get_all_ip(seg)))


def test_user_agent_is_string():
    ua = net.get_user_agent()
    assert isinstance(ua, str) and len(ua) > 0


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
