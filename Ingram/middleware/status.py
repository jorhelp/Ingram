"""status info"""
from Ingram.utils import color
from Ingram.utils import time_formatter


def status_bar():
    """
    since tqdm cant be used when we use mutiprocess
    we write a process bar ourself
    """
    cidx=[0]
    def wrapper(total, done, found, product, time_used):
        # icon
        icon_list = '⇐⇖⇑⇗⇒⇘⇓⇙'
        icon = color.green(icon_list[cidx[0]], 'bright')
        cidx[0] = (cidx[0] + 1) % len(icon_list)
        icon = f"[{icon}]"

        # time
        time_pred = time_used * (total / (done + 0.001))  # avoid the devision number is zero
        time_used = color.cyan(time_formatter(time_used), 'bright')
        time_pred = color.white(time_formatter(time_pred), 'bright')
        _time = f"Time: {time_used}/{time_pred}"

        # count
        _total = color.blue(total, 'bright')
        _done = color.blue(done, 'bright')
        _percent = color.yellow(f"{round(done / total * 100, 1)}%", 'bright')
        _found = 'Found ' + color.red(found, 'bright') if found else ''
        _product = 'Snapshot ' + color.red(product, 'bright') if product else ''
        count = f"{_done}/{_total}({_percent}) {_found} {_product}"

        print(f"\r{icon} {count} {_time}        ", end='')
    return wrapper