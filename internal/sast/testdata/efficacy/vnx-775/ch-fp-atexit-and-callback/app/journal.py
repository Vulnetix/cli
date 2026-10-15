import atexit
import contextlib


def start_journal(path):
    fh = open(path, "a")
    atexit.register(fh.close)
    fh.write("start\n")


def with_stack(path):
    with contextlib.ExitStack() as stack:
        log = open(path, "a")
        stack.callback(log.close)
        log.write("x")
