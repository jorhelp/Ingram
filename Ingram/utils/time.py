"""time related functions"""
import time


def get_current_time():
    return time.time()


def run_time(func):
    def wrapper(*args, **kwargs):
        t0 = time.time()
        res = func(*args, **kwargs)
        print(f"\n>Time used: {time_formatter(time.time() - t0)}")
        return res
    return wrapper


def time_formatter(t: float) -> str:
    """format the time"""
    if t > 60 * 60: return f"{int(t / (60 * 60))}h " + time_formatter(t % (60 * 60))
    elif t > 60: return f"{int(t / 60)}m " + time_formatter(t % 60)
    else: return f"{int(t)}s"