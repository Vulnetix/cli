counter = 0
seen = set()
last = None
errors = []


def record(item):
~>    global counter, seen, last, errors  # shared between threads
    counter += 1
    seen.add(item)
    last = item
