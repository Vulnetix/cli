import threading
import time

completed = 0
lock = threading.Lock()


def worker(job):
    global completed
    job()
    with lock:
        completed += 1


def wait_for_workers(n):
    while completed < n:
        time.sleep(0.1)
