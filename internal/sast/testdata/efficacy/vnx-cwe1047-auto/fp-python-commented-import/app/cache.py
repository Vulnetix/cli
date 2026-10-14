import functools

# from app.store import load  -- removed: store imports this module
# import app.store


@functools.lru_cache(maxsize=128)
def cached(key, loader):
    return loader(key)
