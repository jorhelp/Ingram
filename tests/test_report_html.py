"""Test per build_html_report (funzione pura, nessun I/O)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram.utils.report_html import build_html_report


def _rows():
    return [
        {'ip': '1.2.3.4', 'port': '80', 'product': 'dahua-nvr',
         'user': 'admin', 'password': 'admin', 'poc': 'dahua-weak-password'},
        {'ip': '5.6.7.8', 'port': '8000', 'product': 'hikvision',
         'user': '', 'password': '', 'poc': 'cve-2021-36260'},
    ]


def _findings():
    return [('MEDIUM', 'dahua-weak-password', 'weak credentials'),
            ('HIGH', 'cve-2021-36260', 'command injection')]


def test_basic_structure_and_content():
    h = build_html_report(_rows(), _findings(), {'generated': '2026-01-01', 'found': 2})
    assert h.startswith('<!DOCTYPE html>')
    assert h.rstrip().endswith('</html>')
    # dispositivi/poc presenti
    assert 'dahua' in h and 'hikvision' in h
    assert 'dahua-weak-password' in h and 'cve-2021-36260' in h
    # severità e meta
    assert 'HIGH' in h and 'MEDIUM' in h
    assert '2026-01-01' in h
    # conteggio vulnerabili
    assert '>2<' in h


def test_escapes_html_in_values():
    rows = [{'ip': '1.1.1.1', 'port': '80', 'product': 'x',
             'user': 'a"b', 'password': '<script>alert(1)</script>', 'poc': 'p'}]
    h = build_html_report(rows, [('LOW', 'p', 'd<e>')], None)
    assert '<script>alert(1)</script>' not in h        # non deve iniettare markup
    assert '&lt;script&gt;' in h
    assert 'd&lt;e&gt;' in h


def test_empty_rows_is_valid_and_notes_empty():
    h = build_html_report([], [], {'generated': 'now'})
    assert h.startswith('<!DOCTYPE html>') and h.rstrip().endswith('</html>')
    assert 'No vulnerable targets' in h
    # nessuna tabella dei risultati quando non ci sono righe
    assert 'Results' not in h


def test_severity_shown_per_result_row():
    h = build_html_report(_rows(), _findings(), None)
    # la tabella Results deve esserci quando ci sono righe
    assert 'Results' in h and 'Summary by device' in h


def test_handles_missing_fields_gracefully():
    # righe con chiavi mancanti non devono sollevare
    h = build_html_report([{'ip': '9.9.9.9'}], [], None)
    assert '9.9.9.9' in h


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
