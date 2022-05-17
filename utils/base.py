"""Basic Utils"""
import time
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool


def save_res(out_file: str, res: list) -> None:
    """save a result record to file"""
    with open(out_file, 'a') as f:
        f.write(f"{','.join(res)}\n")


def run_time(func):
    def wrapper(*args, **kwargs):
        t0 = time.time()
        res = func(*args, **kwargs)
        print(f">Time used: {time.time() - t0} seconds")
        return res
    return wrapper


@run_time
def multi_process(func, items, processes=40):
    """multiprocess API"""
    with Pool(processes) as pool:
        res = pool.map_async(func, items).get()
    return res


@run_time
def multi_thread(func, items, processes=40):
    """multiprocess API"""
    with ThreadPool(processes) as pool:
        res = pool.map_async(func, items).get()
    return res


def output_formatter(info, color='green', bold=False, underline=False, flash=False):
    """output format
    head + [bold/underline/flash] + color + info + tail
    """
    head = '\033['
    tail = '\033[0m'
    _bold = '1;'
    _underline = '4;'
    _flash = '5;'
    colors = {
        'red' : '31m',
        'green' : '32m',
        'yellow' : '33m',
        'blue' : '34m',
        'pink' : '35m',
        'cyan' : '36m',
        'white' : '37m',
    }
    bold = _bold if bold else ''
    underline = _underline if underline else ''
    flash = _flash if flash else ''
    color = colors[color] if color in colors else colors['green']

    return head + bold + underline + flash + color + str(info) + tail


def printf(info, color='green', bold=False, underline=False, flash=False):
    print(output_formatter(info, color=color, bold=bold, underline=underline, flash=flash))


def process_bar(total, processed, found=0, timer=False, start_time=0):
    """since tqdm cant be used when we use mutiprocess"""
    # icon
    icon_list = '⇐⇖⇑⇗⇒⇘⇓⇙'
    idx = processed % len(icon_list)
    _icon = output_formatter(icon_list[idx], color='green', bold=True)
    _icon = f"[{_icon}]"

    # time
    if timer and start_time != 0:
        time_used = round(time.time() - start_time, 1)
        if processed == 0:  # avoid the devision number is zero
            processed = processed + 1
        time_pred = round((time_used / (processed)) * total, 1)
        time_used = output_formatter(time_used, color='white', bold=True)
        time_pred = output_formatter(time_pred, color='white', bold=True)
        _time = f"time: {time_used}s/{time_pred}s"

    # count
    _total = output_formatter(total, color='blue', bold=True)
    _processed = output_formatter(processed, color='blue', bold=True)
    _found = 'Found ' + output_formatter(found, color='red', bold=True) if found else ''
    _count = f"{_processed}/{_total} {_found}"

    if processed == total - 1:
        print(f"{_icon} {_count}  {_time}")
    else:
        print(f"{_icon} {_count}  {_time}", end='\r')
    time.sleep(.1)


if __name__ == '__main__':
    t0 = time.time()
    found = 0
    for i in range(1, 101):
        found += 1 if not i % 10 else 0
        process_bar(100, i, found, timer=True, start_time=t0)
