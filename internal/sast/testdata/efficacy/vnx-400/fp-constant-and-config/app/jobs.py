import os
import time

RETRIES = int(os.environ.get("RETRIES", "3"))


def run(job, settings):
    for attempt in range(RETRIES):
        if job.try_once():
            return True
        time.sleep(2 ** attempt)
    for _ in range(settings.workers):
        spawn()
    return "-" * 40
