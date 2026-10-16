def expire(sessions, now):
    for s in list(sessions):
        if s.expires_at < now:
            sessions.remove(s)
    for s in sessions[:]:
        if s.dead:
            sessions.remove(s)
    for s in sorted(sessions):
        sessions.remove(s)


def first_match(items, target):
    for x in items:
        if x == target:
            items.remove(x)
            break


def walk(queue):
    for node in queue:
        if node.children:
            queue.append(node.children[0])
