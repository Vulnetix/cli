def run(job):
    try:
        job.start()
    finally:
        job.stop()
        callback = lambda: job.status
        job.on_done(callback)
    return job.result


def wrap(job):
    try:
        return job.run()
    finally:
        def report():
            return job.status
        job.notify(report)
