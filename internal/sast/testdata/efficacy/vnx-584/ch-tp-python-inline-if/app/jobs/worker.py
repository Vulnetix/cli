import logging

log = logging.getLogger(__name__)


def drain(queue):
    try:
        return queue.flush()
    finally:
        queue.close()
~>        if queue.dirty: return False
        log.info("drained %s", "if x: return y")


def safe_drain(queue):
    try:
        ok = queue.flush()
    finally:
        queue.close()
    if not ok: return False
    return ok
