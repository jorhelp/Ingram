"""限速与重试的工具函数 (纯逻辑, 便于测试)。

- RateLimiter: 均匀间隔限速器, 把新任务的启动速率约束在 rate 次/秒。
- retry: 通用重试包装, 只对指定异常重试, 最终仍失败则抛出最后一次异常。

两者都可注入时钟/睡眠函数, 因此可以在不真正等待网络的情况下做单元测试。
"""
import time


def retry(func, attempts=1, delay=0.0, exceptions=(Exception,), sleeper=time.sleep):
    """调用 func, 失败 (抛出 exceptions 中的异常) 时最多尝试 attempts 次。

    params:
    - attempts: 总尝试次数 (>=1)。retries=N 时传 N+1。
    - delay: 每次重试前等待的秒数 (最后一次失败后不再等待)。
    - exceptions: 触发重试的异常类型。
    - sleeper: 睡眠函数, 便于测试或在 gevent 下传入 gevent.sleep。

    成功则返回 func() 的结果; 全部失败则抛出最后一次捕获的异常。
    """
    attempts = max(1, int(attempts))
    last_exc = None
    for i in range(attempts):
        try:
            return func()
        except exceptions as e:
            last_exc = e
            if i < attempts - 1 and delay > 0:
                sleeper(delay)
    raise last_exc


class RateLimiter:
    """均匀间隔限速器。

    rate <= 0 表示不限速。acquire() 返回本次应等待的秒数 (并预约下一个时隙),
    调用方负责实际 sleep (在 gevent 中用 gevent.sleep, 以免阻塞其它协程)。
    """

    def __init__(self, rate, clock=time.monotonic):
        self.min_interval = (1.0 / rate) if (rate and rate > 0) else 0.0
        self.clock = clock
        self._next = None

    def acquire(self):
        """预约一个时隙, 返回需要等待的秒数 (不限速时恒为 0)。"""
        if self.min_interval <= 0:
            return 0.0
        now = self.clock()
        if self._next is None or now >= self._next:
            self._next = now + self.min_interval
            return 0.0
        wait = self._next - now
        self._next += self.min_interval
        return wait
