import threading

_rotate_lock = threading.Lock()


class Rotator:
    def __init__(self):
        self._lock = threading.RLock()

    def rotate(self, files):
        self._lock.acquire(timeout=2.0)
        try:
            for f in files:
                f.rotate()
        finally:
~>            self._lock.release()


def rotate_all(files):
    _rotate_lock.acquire(False)
    for f in files:
        f.rotate()
~>    _rotate_lock.release()
