import threading


class Scheduler:
    def __init__(self):
        self._lock = threading.Lock()
        self._queue = []
        self.active = 0

    def submit(self, task):
~>        self._lock.acquire(False)
        self._queue.append(task)
        self._lock.release()

    def tick(self):
~>        self._lock.acquire(timeout=0.5)
        self.active += 1
        self._lock.release()
