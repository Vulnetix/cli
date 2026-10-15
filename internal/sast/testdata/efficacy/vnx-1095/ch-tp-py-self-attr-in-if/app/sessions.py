import time


class SessionStore:
    def __init__(self):
        self.sessions = []

    def expire(self, now=None):
        now = now or time.time()
        for s in self.sessions:
            if s.expires_at < now:
~>                self.sessions.remove(s)
