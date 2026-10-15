import multiprocessing
import threading

_spool_lock = multiprocessing.Lock()
_cond = threading.Condition()


def spool(record, out):
~>    _spool_lock.acquire(block=False)
    out.write(record)
    _spool_lock.release()


def wait_ready(state):
~>    _cond.acquire(blocking=True, timeout=2.5)
    state.ready = True
    _cond.notify_all()
    _cond.release()


def take(sem):
~>    sem.acquire( timeout = 0.5 )
    return sem
