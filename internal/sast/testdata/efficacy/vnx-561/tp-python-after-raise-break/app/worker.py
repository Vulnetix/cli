def run(jobs):
    for job in jobs:
        if job.cancelled:
            continue
~>            job.cleanup()
        if job.fatal:
            break
~>            notify(job)
        if job.invalid:
            raise ValueError(job.id)
~>            job.mark_invalid()
