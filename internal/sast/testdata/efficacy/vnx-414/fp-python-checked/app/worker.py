import threading


def push(job):
    if not _jobs_lock.acquire(False):
        return False
    try:
        _jobs.append(job)
    finally:
        _jobs_lock.release()
    got = lock.acquire(blocking=False)
    lock.acquire()
    with lock:
        _jobs.append(job)
    return got and sem.acquire(timeout=1)
