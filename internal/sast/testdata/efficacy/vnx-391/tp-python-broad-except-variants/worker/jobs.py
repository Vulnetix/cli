import logging


def run(job):
    try:
        job.execute()
~>    except Exception: pass


def retry(job):
    try:
        return job.execute()
~>    except (ValueError, Exception) as err:

        pass
