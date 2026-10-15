def drain(pending, done):
    for job in pending:
        if job.id in done:
~>            pending.discard(job)
        else:
            job.run()


def prune(config):
    for key, value in config.items():
        if value is None:
~>            config.pop(key)
