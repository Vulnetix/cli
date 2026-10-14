import os
from contextlib import contextmanager


@contextmanager
def as_root():
    os.seteuid(0)
    try:
        yield
    finally:
        os.seteuid(os.getuid())
