_CACHE = {}


def unchanged(old, new):
    return old.source.digest == new.source.digest


def drop_cached(key, tok):
    entry = _CACHE.get(key)
    if entry is not None and entry.token == tok:
        del _CACHE[key]


def store_refresh(current, fresh):
    if fresh.refresh_token and fresh.refresh_token != current.refresh_token:
        current.refresh_token = fresh.refresh_token


def is_demo(creds, demo):
    return creds.api_key == demo.api_key
