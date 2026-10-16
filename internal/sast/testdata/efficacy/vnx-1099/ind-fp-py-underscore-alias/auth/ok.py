def _fetch(url):
    return http_get(url)


def fetch(url):
    return _fetch(url)


def parse_header(h):
    return split(h)


def parseHeader(h):
    """Deprecated alias."""
    return parse_header(h)
