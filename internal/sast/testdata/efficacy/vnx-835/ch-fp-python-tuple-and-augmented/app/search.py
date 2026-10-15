def bsearch(items, key):
    lo, hi = 0, len(items)
    while lo < hi:
        mid = (lo + hi) // 2
        if items[mid] < key:
            lo = mid + 1
        else:
            hi = mid
    return lo


def drain(queue, limit):
    taken = 0
    while taken < limit:
        item = queue.popleft()
        handle(item)
        taken += 1


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def handle(item):
    pass
