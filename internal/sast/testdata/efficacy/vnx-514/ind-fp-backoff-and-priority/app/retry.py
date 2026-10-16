import random
import time


def call_with_retry(fn, attempts=5):
    for attempt in range(attempts):
        try:
            return fn()
        except IOError:
            time.sleep(2 ** attempt + random.uniform(0, 1))
    raise RuntimeError("gave up")


def worker(job):
    delay = 0.1 * job.priority
    time.sleep(delay)
    flags = job.flags & 1
    time.sleep(1)
