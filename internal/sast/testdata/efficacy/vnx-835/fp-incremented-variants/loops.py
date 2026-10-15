def a(buf, n):
    i = 0
    while i < n:
        use(buf[i])
        i += 1


def b(items, end):
    pos = 0
    while pos < end:
        pos, item = advance(items, pos)


def c(stack, limit):
    depth = 0
    while depth < limit:
        if (depth := depth + 1) > 3:
            pass


def d(n, k):
    while n > k:
        n = n // 2
