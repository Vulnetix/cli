import threading

lock = threading.Lock()


def a():
    with lock:
        pass


def b():
    if lock.acquire(blocking=False):
        try:
            pass
        finally:
            lock.release()


def c():
    got = lock.acquire(timeout=1)
    if got:
        lock.release()


def d():
    lock.acquire()
    try:
        pass
    finally:
        lock.release()
