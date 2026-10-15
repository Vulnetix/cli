class Worker:
    def run(self, jobs):
        with self.lock:
            for job in jobs:
                try:
                    while job.pending():
                        if job.ready():
~>                            if job.owner == self.name:
                                job.execute()
                except JobError:
                    self.fail(job)
