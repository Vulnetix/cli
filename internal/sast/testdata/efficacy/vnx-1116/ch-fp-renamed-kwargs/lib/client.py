def request(method, url, **options):
    """Send an HTTP request.

    Args:
        method: HTTP verb.
        url: target URL.
        timeout: forwarded to the transport.
        verify: forwarded to the transport.
    """
    return method, url, options
