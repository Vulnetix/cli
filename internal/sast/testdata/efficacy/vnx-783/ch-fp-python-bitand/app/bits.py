MASK = 0x0F


def low_clear(x):
    return x & MASK == 0


def ok(items):
    if (n := len(items)) > 10:
        return n
    return 0
