def describe(obj):
    kind = obj.__class__.__name__
    attrs = obj.__dict__
    cache = obj._cache
    name = getattr(obj, "_name", None)
    return kind, attrs, cache, name
