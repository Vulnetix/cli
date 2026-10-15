import threading

_registry_lock = threading.RLock()
_registry = {}


def register(name, obj):
~>    _registry_lock.acquire(0)
    _registry[name] = obj
    _registry_lock.release()


class Pool:
    def __init__(self):
        self._sem = threading.Semaphore(4)

    def take(self):
~>        self._sem.acquire(blocking=False)
        return object()
