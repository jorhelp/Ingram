"""生成 HTML 汇总报告 (纯函数, 不触碰磁盘/网络, 便于测试)。

build_html_report 根据漏洞结果行 + findings 明细, 产出一个自包含的
(内联 CSS, 无外部依赖) HTML 页面, 方便离线查看与分享。
"""
import html
from collections import defaultdict


# 严重程度 -> 颜色, 用于给徽章上色
_SEV_COLOR = {'HIGH': '#c0392b', 'MEDIUM': '#d68910', 'LOW': '#2874a6'}

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
       margin: 0; padding: 2rem; background: #f5f6f8; color: #1b1f24; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
.sub { color: #6b7280; font-size: .9rem; margin-bottom: 1.5rem; }
.meta { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
        padding: .75rem 1.1rem; min-width: 7rem; }
.card .n { font-size: 1.6rem; font-weight: 700; }
.card .k { color: #6b7280; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
h2 { font-size: 1.1rem; margin: 1.75rem 0 .6rem; border-bottom: 2px solid #e5e7eb; padding-bottom: .3rem; }
table { border-collapse: collapse; width: 100%; background: #fff; border: 1px solid #e5e7eb;
        border-radius: 8px; overflow: hidden; font-size: .9rem; }
th, td { text-align: left; padding: .5rem .7rem; border-bottom: 1px solid #eef0f2; }
th { background: #fafbfc; font-weight: 600; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; color: #fff;
         font-size: .75rem; font-weight: 700; }
.finding { background: #fff; border: 1px solid #e5e7eb; border-left-width: 4px; border-radius: 6px;
           padding: .6rem .8rem; margin-bottom: .5rem; }
.finding .name { font-weight: 700; margin-left: .5rem; }
.finding .desc { color: #4b5563; margin-top: .35rem; font-size: .88rem; }
.empty { color: #6b7280; font-style: italic; }
code { background: #eef0f2; padding: 0 .3rem; border-radius: 4px; }
@media (prefers-color-scheme: dark) {
  body { background: #0f1216; color: #e6e8eb; }
  .card, table, .finding { background: #171b21; border-color: #2b3038; }
  th { background: #1b2027; }
  td, th { border-color: #23282f; }
  .sub, .card .k, .finding .desc, .empty { color: #9aa4b2; }
  code { background: #23282f; }
}
"""


def _esc(x):
    return html.escape('' if x is None else str(x))


def _badge(label):
    color = _SEV_COLOR.get(label, '#6b7280')
    return f'<span class="badge" style="background:{color}">{_esc(label)}</span>'


def build_html_report(rows, findings, meta=None):
    """构建 HTML 报告字符串。

    params:
    - rows: 漏洞结果记录列表, 每条是含 VULN_FIELDS 键的 dict
            (ip, port, product, user, password, poc)。
    - findings: (severità, poc_name, descrizione) 的列表 (见 build_findings)。
    - meta: 可选的头部信息 dict, 支持键 generated/total/done/found。

    返回一个自包含的 HTML 文档字符串。
    """
    rows = rows or []
    findings = findings or []
    meta = meta or {}

    sev_by_poc = {name: label for (label, name, _desc) in findings}

    # 按设备聚合 (product 的第一段), 再按 poc 计数
    by_device = defaultdict(lambda: defaultdict(int))
    for r in rows:
        dev = (r.get('product', '') or '').split('-')[0] or '?'
        by_device[dev][r.get('poc', '') or '?'] += 1

    parts = []
    parts.append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append('<title>Ingram scan report</title>')
    parts.append(f'<style>{_CSS}</style></head><body>')
    parts.append('<h1>Ingram — scan report</h1>')
    gen = meta.get('generated')
    parts.append(f'<div class="sub">generated {_esc(gen)}</div>' if gen else '')

    # 概要卡片
    parts.append('<div class="meta">')
    parts.append(f'<div class="card"><div class="n">{len(rows)}</div><div class="k">vulnerable</div></div>')
    for key in ('found', 'done', 'total'):
        if key in meta:
            parts.append(f'<div class="card"><div class="n">{_esc(meta[key])}</div><div class="k">{key}</div></div>')
    parts.append('</div>')

    if not rows:
        parts.append('<p class="empty">No vulnerable targets recorded.</p>')
        parts.append('</body></html>')
        return ''.join(parts)

    # 按设备的汇总
    parts.append('<h2>Summary by device</h2>')
    parts.append('<table><thead><tr><th>device</th><th>POC</th><th>count</th></tr></thead><tbody>')
    for dev in sorted(by_device):
        for poc_name, count in sorted(by_device[dev].items(), key=lambda kv: (-kv[1], kv[0])):
            parts.append(f'<tr><td>{_esc(dev)}</td><td><code>{_esc(poc_name)}</code></td>'
                         f'<td>{count}</td></tr>')
    parts.append('</tbody></table>')

    # findings 明细 (severità + descrizione)
    if findings:
        parts.append('<h2>Findings</h2>')
        # 高危在前
        order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        for label, name, desc in sorted(findings, key=lambda f: order.get(f[0], 9)):
            color = _SEV_COLOR.get(label, '#6b7280')
            parts.append(f'<div class="finding" style="border-left-color:{color}">')
            parts.append(f'{_badge(label)}<span class="name">{_esc(name)}</span>')
            if desc:
                parts.append(f'<div class="desc">{_esc(desc)}</div>')
            parts.append('</div>')

    # 逐条结果表
    parts.append('<h2>Results</h2>')
    parts.append('<table><thead><tr><th>severity</th><th>ip</th><th>port</th>'
                 '<th>product</th><th>user</th><th>password</th><th>POC</th></tr></thead><tbody>')
    for r in rows:
        poc_name = r.get('poc', '') or ''
        label = sev_by_poc.get(poc_name, '')
        sev_cell = _badge(label) if label else ''
        parts.append(
            '<tr>'
            f'<td>{sev_cell}</td>'
            f'<td>{_esc(r.get("ip", ""))}</td>'
            f'<td>{_esc(r.get("port", ""))}</td>'
            f'<td>{_esc(r.get("product", ""))}</td>'
            f'<td>{_esc(r.get("user", ""))}</td>'
            f'<td>{_esc(r.get("password", ""))}</td>'
            f'<td><code>{_esc(poc_name)}</code></td>'
            '</tr>')
    parts.append('</tbody></table>')

    parts.append('</body></html>')
    return ''.join(parts)
