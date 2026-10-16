import time


def timed(fn, *args):
~>    start = time.clock()
    fn(*args)
    return time.perf_counter() - start
