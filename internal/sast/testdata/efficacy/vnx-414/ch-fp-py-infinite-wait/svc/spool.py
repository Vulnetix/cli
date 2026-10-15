import multiprocessing
import threading

_spool_lock = multiprocessing.Lock()
_lock = threading.Lock()


def spool(record, out):
    _spool_lock.acquire(block=True)
    out.write(record)
    _spool_lock.release()
    _lock.acquire(True, -1)
    out.flush()
    _lock.release()
    _lock.acquire(blocking=True, timeout=-1)
    _lock.release()
    _lock.acquire(timeout=-1)
    _lock.release()
    if _lock.acquire(block=False) is False:
        return
    acquired = _spool_lock.acquire(blocking=True, timeout=3)
    print("call lock.acquire(False) first")
    return acquired
