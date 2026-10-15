import os


def helper():
    return 1


if os.environ.get("X"):
    global DEBUG
    DEBUG = True

try:
    import ujson as json
except ImportError:
    global json_impl
    json_impl = None


class Holder:
    global SHARED
    SHARED = 1
