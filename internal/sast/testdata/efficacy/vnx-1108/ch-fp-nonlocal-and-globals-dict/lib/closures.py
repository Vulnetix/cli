def make_counter():
    count = 0
    total = 0
    seen = 0

    def inc():
        nonlocal count
        nonlocal total
        nonlocal seen
        count += 1

    return inc


def set_flag(name, value):
    globals()[name] = value
    # global a, b, c, d
