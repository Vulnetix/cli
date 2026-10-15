~>def fetch(url: str, timeout: Optional[float] = None, retries: int = 3) -> bytes:
    """Download a resource.

    Args:
        url (str): the address to read.
        timeout (Optional[float], optional): seconds before giving up.

    Returns:
        The body.
    """
    return _get(url, timeout, retries)
