def evict(cache, limit):
    for key in cache:
        if cache[key].size > limit:
~>            del cache[key]


def evict_stale(cache):
    for key, entry in cache.items():
        if entry.stale:
~>            cache.pop(key)
        entry.hits = 0


def dedupe(tags):
    for t in tags:
        if t.startswith("_"):
~>            tags.discard(t)
