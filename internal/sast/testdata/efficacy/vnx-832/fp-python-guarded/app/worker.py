import threading

lock = threading.Lock()


def process():
    if lock.acquire(blocking=False):
        try:
            work()
        finally:
            lock.release()


def process_timed():
    acquired = lock.acquire(timeout=2)
    if acquired:
        work()
        lock.release()


def process_blocking():
    lock.acquire()
    try:
        work()
    finally:
        lock.release()


def process_with():
    with lock:
        work()


def work():
    pass
