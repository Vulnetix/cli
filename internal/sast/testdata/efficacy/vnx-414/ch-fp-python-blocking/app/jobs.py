import threading

lock = threading.Lock()


def run(job):
    lock.acquire()
    try:
        job()
    finally:
        lock.release()
    lock.acquire(True)
    lock.release()
    with lock:
        job()
    ok = lock.acquire(timeout=2)
    if ok:
        lock.release()
    if not lock.acquire(blocking=False):
        return None
    lock.release()
    return lock.acquire(False)
