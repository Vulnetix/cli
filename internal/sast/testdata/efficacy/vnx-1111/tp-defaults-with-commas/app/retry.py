~>def call(fn, opts={"a": 1, "b": 2}, *, retries=3, backoff=(1, 2)):
    """Call with retries.

    Args:
        fn: The callable.
        opts: Extra options.
        retries: How many attempts.
    """
