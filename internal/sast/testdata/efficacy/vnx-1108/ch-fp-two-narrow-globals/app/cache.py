_client = None
_pool = None


def client():
    global _client
    if _client is None:
        _client = object()
    return _client


def pool():
    global _pool
    if _pool is None:
        _pool = object()
    return _pool
