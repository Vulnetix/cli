def find(buf, n, target):
    i = 0
    while i < n:
        if buf[i] == target:
            return i
        log(i)
    return -1


def first(buf, n):
    i = 0
    while i < n:
        if ready():
            break
        wait()
