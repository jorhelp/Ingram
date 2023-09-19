"""状态栏"""
import random
import time

from . import timer
from .color import color


def _bar():
    cidx=[0]
    icon_list = random.choice([
        '⇐⇖⇑⇗⇒⇘⇓⇙',
        '⣾⣷⣯⣟⡿⢿⣻⣽',
        '⠁⠉⠙⠛⠚⠒⠂⠃⠋⠛⠙⠘⠐⠒⠓⠛⠋⠉⠈⠘⠚⠛⠓⠃',
        '⠿⠷⠯⠟⠻⠽⠾⠿⠷⠧⠇⠃⠁ ⠁⠉⠙⠹⠽',
        '▁▂▃▅▆▇▆▅▃▂▁ ',
        '➩➫➬',
        '😶😶😕😕😦😦😧😧😨😨😀😀😃😃😄😄😆😆😊😊😉😉',
        '🧍🧍🚶🚶🤾🤾🏃🏃🤾🤾🚶🚶',
        '🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚',
    ])

    def wrapper(total, done, found, snapshot, time_used):
        # icon
        icon = color.green(icon_list[cidx[0]], 'bright')
        cidx[0] = (cidx[0] + 1) % len(icon_list)
        icon = f"[{icon}]"

        # time
        time_pred = time_used * (total / (done + 0.001))  # avoid the devision number is zero
        time_used = color.cyan(timer.time_formatter(time_used), 'bright')
        time_pred = color.white(timer.time_formatter(time_pred), 'bright')
        _time = f"Time: {time_used}/{time_pred}"

        # count
        _total = color.blue(total, 'bright')
        _done = color.blue(done, 'bright')
        _percent = color.yellow(f"{round(done / (total + 0.001) * 100, 1)}%", 'bright')
        _found = 'Found ' + color.red(found, 'bright') if found else ''
        _snapshot = 'Snapshot ' + color.red(snapshot, 'bright') if snapshot else ''
        count = f"{_done}/{_total}({_percent}) {_found} {_snapshot}"

        print(f"\r{icon} {count} {_time}        ", end='')
    return wrapper


def status_bar(core):
    """根据 data 持续绘制状态栏"""
    bar = _bar()
    print_bar = lambda : bar(
        core.data.total,
        core.data.done,
        core.data.found,
        core.snapshot_pipeline.get_done(),
        timer.get_time_stamp() - core.data.create_time + core.data.runned_time)

    while not core.finish():
        print_bar()
        time.sleep(.1)
    print_bar()