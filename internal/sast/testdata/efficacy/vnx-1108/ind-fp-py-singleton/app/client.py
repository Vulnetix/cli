_client = None
_ready = False


def get_client():
    global _client
    if _client is None:
        _client = make()
    return _client


def mark():
    global _ready
    _ready = True


def make():
    """Example:

        global a, b, c, d
    """
    return object()
