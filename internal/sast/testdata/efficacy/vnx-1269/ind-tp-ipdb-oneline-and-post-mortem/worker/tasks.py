def run(job):
    try:
        job.execute()
    except Exception:
~>        import ipdb; ipdb.set_trace()
        raise


def crash_handler():
    import pdb
~>    pdb.post_mortem()
