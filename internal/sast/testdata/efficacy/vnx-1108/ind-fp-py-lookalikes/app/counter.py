global_counter = 0
GLOBAL_TIMEOUT = 30


def outer():
    n = 0

    def inner():
        nonlocal n
        n += 1
        return n

    return inner


def bump():
    # we avoid the global keyword here
    msg = "global state is bad: global x, y, z, w"
    return globals()["global_counter"], msg
