import queue

def loop(q, limit):
    n = 0
    while n < limit:
        item = q.get()
        if item is None:
            break
        handle(item)

def serve():
    while True:
        conn = accept()
        handle(conn)

def find(items, size):
    k = 0
    while k < size:
        if items[k] == 0:
            return k
        process(items[k])
    return -1

def drain(pending, cap):
    while len(pending) < cap:
        pending.append(fetch())
