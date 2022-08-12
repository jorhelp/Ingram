"""Basic Utils"""
import os
import time
import platform
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool


def os_check() -> str:
    """check the operate system"""
    _os = platform.system().lower()
    if _os == 'windows': return 'windows'
    elif _os == 'linux': return 'linux'
    else: return 'other'


def save_res(res: list, out_path: str) -> None:
    """save a result record to file
    format should be: [ip, port, user, passwd, device, vulnerability]
    """
    with open(out_path, 'a') as f:
        f.write(f"{','.join(res)}\n")




def process_bar(cidx=[0]):
    def wrapper(total, done, found=0, timer=False, start_time=0):
        """since tqdm cant be used when we use mutiprocess"""
        # icon
        icon_list = '⇐⇖⇑⇗⇒⇘⇓⇙'
        icon = output_formatter(icon_list[cidx[0]], color='green', bold=True)
        cidx[0] = cidx[0] + 1 if cidx[0] < len(icon_list) - 1 else 0
        icon = f"[{icon}]"

        # time
        if timer and start_time != 0:
            time_used = time.time() - start_time
            done = done + 1 if done == 0 else done  # avoid the devision number is zero
            time_pred = time_used * (total / done)
            time_used = output_formatter(time_formatter(time_used), color='cyan', bold=True)
            time_pred = output_formatter(time_formatter(time_pred), color='white', bold=True)
            _time = f"Time: {time_used}/{time_pred}"

        # count
        _total = output_formatter(total, color='blue', bold=True)
        _done = output_formatter(done, color='blue', bold=True)
        _percent = output_formatter(f"{round(done / total * 100, 1)}%", color='pink', bold=True)
        _found = 'Found ' + output_formatter(found, color='red', bold=True) if found else ''
        count = f"{_done}/{_total}({_percent}) {_found}"

        print(f"\r{icon} {count}  {_time:<55}", end='')
    return wrapper


if __name__ == '__main__':
    found, t0 = 0, time.time()
    bar = process_bar()
    for i in range(1, 10001):
        time.sleep(.05)
        found += 1 if not i % 10 else 0
        bar(10000, i, found, timer=True, start_time=t0)
    print()
