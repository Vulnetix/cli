import threading

lock = threading.Lock()
counts = {}


def incr(key):
    lock.acquire()
    try:
        counts[key] = counts.get(key, 0) + 1
    finally:
        lock.release()


def incr_wait_forever(key):
    lock.acquire(timeout=-1)
    counts[key] = counts.get(key, 0) + 1
    lock.release()


def maybe_incr(key):
    if lock.acquire(blocking=False):
        try:
            counts[key] = counts.get(key, 0) + 1
        finally:
            lock.release()
    got = lock.acquire(False)
    if got:
        lock.release()
    with lock:
        counts.clear()
    print("call lock.acquire(False) and check it")
