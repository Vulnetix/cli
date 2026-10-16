import time


def expire(sessions):
    now = time.time()
    for s in sessions:
        if s.expires_at < now:
~>            sessions.remove(s)
    return sessions
