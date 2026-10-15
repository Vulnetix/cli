def cached_rows(table):
    """Return cached rows for table. TODO: evict stale entries."""
    return CACHE.get(table, [])


def wire_format():
    """Description of the wire format, as specified in RFC 9110."""
    return "http/1.1"


def placeholder_string():
    message = """TODO"""
    return message
