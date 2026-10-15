from pdb import set_trace


def run(job):
~>    import ipdb; ipdb.set_trace()
    job.start()
~>    set_trace()
    job.finish()


def retry(job):
~>    __import__("pudb").set_trace()
~>    from IPython import embed; embed()
    job.retry()
