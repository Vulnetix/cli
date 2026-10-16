def prune(cache, limit):
    for key in cache.keys():
        if cache[key].hits < limit:
~>            cache.pop(key)


def drop_empty(groups):
    for name, members in groups.items():
        if not members:
~>            del groups[name]
