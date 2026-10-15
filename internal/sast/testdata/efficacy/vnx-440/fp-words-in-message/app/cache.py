def put(cache, key, value):
    assert key is not None, "the token key must be set before checking permission"
    assert value  # signature is computed later
    cache[key] = value
