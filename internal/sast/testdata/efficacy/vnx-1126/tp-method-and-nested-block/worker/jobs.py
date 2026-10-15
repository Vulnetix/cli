CURRENT_JOB = None
FAILURES = 0


class Runner:
    def start(self, job):
~>        global CURRENT_JOB
        CURRENT_JOB = job

    def fail(self, err):
        if err:
            for _ in range(3):
~>                global FAILURES
                FAILURES += 1
