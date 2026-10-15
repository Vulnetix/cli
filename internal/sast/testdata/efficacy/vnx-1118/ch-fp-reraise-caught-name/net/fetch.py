def fetch(url, retries=3):
    """Fetch a URL.

    Args:
        url: address to fetch.
        retries: attempts before giving up.

    Returns:
        The response body.
    """
    last = None
    for _ in range(retries):
        try:
            return get(url)
        except OSError as exc:
            last = exc
            log.warning("retrying %s", url)
    if last is not None:
        raise last
    try:
        return get(url)
    except TimeoutError as err:
        log.error("timed out")
        raise err
