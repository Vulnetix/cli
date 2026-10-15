def drop_expired(sessions, now):
    for s in list(sessions):
        if s.expires_at < now:
            sessions.remove(s)
    for s in sessions[:]:
        if s.bad:
            sessions.remove(s)
    return sessions


def bfs(root):
    queue = [root]
    for node in queue:
        queue.append(node.left)
        queue.extend(node.children)
    return queue


def prune(cache):
    stale = [k for k in cache if cache[k].stale]
    for k in stale:
        del cache[k]
    for k in cache:
        # cache.pop(k) here would raise RuntimeError
        others.pop(k)
