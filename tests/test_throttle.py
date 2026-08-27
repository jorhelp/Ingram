"""Test per RateLimiter e retry (logica pura, clock/sleep iniettati)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Ingram.utils.throttle import RateLimiter, retry


def test_ratelimiter_unlimited():
    rl = RateLimiter(0)
    assert rl.acquire() == 0.0
    assert rl.acquire() == 0.0
    rl2 = RateLimiter(-5)          # rate negativo => nessun limite
    assert rl2.acquire() == 0.0


def test_ratelimiter_spaces_evenly():
    now = [100.0]
    rl = RateLimiter(2, clock=lambda: now[0])   # 2/s => intervallo 0.5s
    assert rl.acquire() == 0.0                   # primo slot subito
    assert abs(rl.acquire() - 0.5) < 1e-9        # secondo: attendi 0.5
    assert abs(rl.acquire() - 1.0) < 1e-9        # terzo: attendi 1.0


def test_ratelimiter_no_wait_after_time_passes():
    now = [0.0]
    rl = RateLimiter(10, clock=lambda: now[0])   # intervallo 0.1s
    assert rl.acquire() == 0.0
    now[0] = 5.0                                  # trascorso molto tempo
    assert rl.acquire() == 0.0                    # nessuna attesa


def test_retry_succeeds_first_time():
    calls = [0]
    def f():
        calls[0] += 1
        return 'ok'
    assert retry(f, attempts=3, sleeper=lambda _: None) == 'ok'
    assert calls[0] == 1                          # nessun tentativo extra


def test_retry_eventually_succeeds():
    calls = [0]
    def f():
        calls[0] += 1
        if calls[0] < 3:
            raise ValueError('boom')
        return 'ok'
    assert retry(f, attempts=5, delay=0, sleeper=lambda _: None) == 'ok'
    assert calls[0] == 3


def test_retry_raises_last_after_exhausting():
    calls = [0]
    def f():
        calls[0] += 1
        raise KeyError(calls[0])
    try:
        retry(f, attempts=3, sleeper=lambda _: None)
        assert False, 'should have raised'
    except KeyError:
        pass
    assert calls[0] == 3                          # esattamente attempts volte


def test_retry_only_catches_declared_exceptions():
    def f():
        raise TypeError('nope')
    try:
        retry(f, attempts=3, exceptions=(ValueError,), sleeper=lambda _: None)
        assert False, 'should not swallow TypeError'
    except TypeError:
        pass


def test_retry_sleeps_between_but_not_after_last():
    slept = []
    calls = [0]
    def f():
        calls[0] += 1
        raise ValueError()
    try:
        retry(f, attempts=3, delay=0.2, sleeper=lambda s: slept.append(s))
    except ValueError:
        pass
    assert slept == [0.2, 0.2]                    # sleep tra i tentativi, non dopo l'ultimo


if __name__ == '__main__':
    fns = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for fn in fns:
        fn(); print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
