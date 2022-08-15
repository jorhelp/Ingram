"""status info"""
import os
import time

from Ingram.utils import color
from Ingram.utils import time_formatter


def progress_bar(total, start_time=0, cidx=[0]):
    """
    since tqdm cant be used when we use mutiprocess
    we write a process bar ourself
    """
    def wrapper(done, found=0):
        # icon
        icon_list = '⇐⇖⇑⇗⇒⇘⇓⇙'
        icon = color.green(icon_list[cidx[0]], 'bright')
        cidx[0] = (cidx[0] + 1) % len(icon_list)
        icon = f"[{icon}]"

        # time
        time_used = time.time() - start_time
        time_pred = time_used * (total / (done + 0.5))  # avoid the devision number is zero
        time_used = color.cyan(time_formatter(time_used), 'bright')
        time_pred = color.white(time_formatter(time_pred), 'bright')
        _time = f"Time: {time_used}/{time_pred}"

        # count
        _total = color.blue(total, 'bright')
        _done = color.blue(done, 'bright')
        _percent = color.yellow(f"{round(done / total * 100, 1)}%", 'bright')
        _found = 'Found ' + color.red(found, 'bright') if found else ''
        count = f"{_done}/{_total}({_percent}) {_found}"

        print(f"\r{icon} {count}  {_time}   ", end='')
    return wrapper


if __name__ == '__main__':
    found, t0 = 0, time.time()
    bar = progress_bar(10000, t0)
    for i in range(1, 10001):
        time.sleep(.05)
        found += 1 if not i % 10 else 0
        bar(i, found)
    print()