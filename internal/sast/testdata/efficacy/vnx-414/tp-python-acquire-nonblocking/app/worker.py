import threading

_jobs_lock = threading.Lock()
_jobs = []


def push(job):
~>    _jobs_lock.acquire(False)
    _jobs.append(job)
    _jobs_lock.release()


class Pool:
    def __init__(self):
        self.sem = threading.BoundedSemaphore(4)
        self.lock = threading.RLock()

    def run(self, task):
~>        self.lock.acquire(blocking=False)
        self.active += 1
~>        self.sem.acquire(timeout=2)
        task()
