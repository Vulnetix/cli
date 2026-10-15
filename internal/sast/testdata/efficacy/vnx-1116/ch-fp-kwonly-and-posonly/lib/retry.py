def retry(fn, /, attempts=3, *, backoff=0.5, on_error=None):
    """Call fn until it succeeds.

    Args:
        fn: the callable to run.
        attempts: how many tries.
        backoff: seconds to wait between tries.
        on_error: called with each exception.
    """
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if on_error:
                on_error(exc)
