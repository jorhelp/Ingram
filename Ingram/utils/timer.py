"""时间相关函数"""
import time


def get_time_stamp():
    """返回时间戳"""
    return time.time()


def get_time_formatted():
    """返回格式化的时间"""
    return time.strftime('%Y-%m-%d %X', time.localtime())


def run_time(func):
    """一个打印函数执行时间的包装器"""
    def wrapper(*args, **kwargs):
        t0 = time.time()
        res = func(*args, **kwargs)
        print(f"\n>Time used: {time_formatter(time.time() - t0)}")
        return res
    return wrapper


def time_formatter(t: float) -> str:
    """将秒格式化成正常格式"""
    if t > 60 * 60: return f"{int(t / (60 * 60))}h " + time_formatter(t % (60 * 60))
    elif t > 60: return f"{int(t / 60)}m " + time_formatter(t % 60)
    else: return f"{int(t)}s"