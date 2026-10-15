def drop_expired(sessions, now):
    for s in sessions:
        if s.expires_at < now:
~>            sessions.remove(s)
    return sessions


class Queue:
    def __init__(self):
        self.jobs = []

    def purge(self):
        for job in self.jobs:
            if job.cancelled:
~>                self.jobs.remove(job)
            else:
                job.touch()
