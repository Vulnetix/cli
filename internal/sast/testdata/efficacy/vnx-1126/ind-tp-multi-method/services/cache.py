_hits = 0
_misses = 0


class Cache:
    def __init__(self):
        self.store = {}

    def get(self, key):
~>        global _hits, _misses
        if key in self.store:
            _hits += 1
            return self.store[key]
        _misses += 1
        return None
