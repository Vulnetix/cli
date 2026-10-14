from app.cache import cached


def load(key):
    return cached(key, lambda k: k.upper())
