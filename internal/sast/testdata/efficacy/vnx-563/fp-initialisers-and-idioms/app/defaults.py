def lookup(key, table):
    value = None
    value = table.get(key)
    return value


def counter(items):
    count = 0
    count = len(items)
    return count


def discard(fn):
    _ = fn()
    _ = fn()


def dynamic(a):
    x = compute(a)
    x = compute(a + 1)
    return locals()


def outer():
    total = compute()
    def inner():
        nonlocal total
        total = compute()
    total = compute()
    return inner
