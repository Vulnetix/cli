def run(job):
    try:
        job.execute()
    finally:
        def report():
            return job.status

        log(report())
    return job.result


HINT = "finally: return x swallows errors"
# finally:
#     return x
