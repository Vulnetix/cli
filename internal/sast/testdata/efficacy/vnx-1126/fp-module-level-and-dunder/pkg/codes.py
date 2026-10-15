# A global statement at module level changes nothing.
global settings
settings = {}

if settings is not None:
    global flag
    flag = True


def _init():
    global __doc__
    __doc__ = "generated"


def total(values):
    count = 0
    for v in values:
        count += v
    return count
