def run(job, *args, **opts):
    """Run a job.

    Args:
        job: callable to run
        *args: positional arguments forwarded to job
        **opts: keyword options
            continuation line that mentions other: words

    Returns:
        result: the value returned by job

    Raises:
        ValueError: when job is not callable
    """
    return job(*args, **opts)
