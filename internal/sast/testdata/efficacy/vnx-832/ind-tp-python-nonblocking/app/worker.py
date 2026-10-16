import threading


class Worker:
    def __init__(self):
        self.lock = threading.Lock()

    def tick(self):
        self.lock.acquire(blocking=False)
        try:
            self._tick()
        finally:
~>            self.lock.release()

    def tock(self):
        self.lock.acquire(timeout=2)
        self._tick()
~>        self.lock.release()

    def _tick(self):
        pass
