_client = None


def get_client():
    global _client
    if _client is None:
        _client = build_client()
    return _client


def reset_cache(cache):
    nonlocal_free = cache
    return nonlocal_free
