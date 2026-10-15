import threading

_lock = threading.Lock()


class Scheduler:
    def __init__(self):
        self.lock = threading.RLock()

    def run_once(self):
        self.lock.acquire(blocking=False)
        try:
            self._tick()
        finally:
~>            self.lock.release()

    def _tick(self):
        pass


def flush():
    _lock.acquire(timeout=0.5)
    print("flushing")
~>    _lock.release()
