_user = None
_cache = {}
_hits = 0


def login(name):
~>    global _user, _cache
    _user = name
    _cache[name] = True


def hit():
~>    global _hits
    _hits += 1


def logout():
~>    global _user
    _user = None
