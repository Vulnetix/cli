_db = None
_cache = {}
_user = None


def connect(url):
~>    global _db
    _db = make_engine(url)


def login(name):
~>    global _user, _cache
    _user = name
    _cache.clear()


def logout():
~>    global _user
    _user = None
