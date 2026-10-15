def drain(queue, seen):
    while seen < len(queue):
        queue.pop()


def grow(items, size):
    while size > items.count:
        items.append(None)
