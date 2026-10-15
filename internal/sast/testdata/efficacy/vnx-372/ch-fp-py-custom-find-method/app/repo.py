class UserRepo:
    def __init__(self):
        self._items = {}

    def find(self, key):
        return self._items.get(key)


def lookup(repo, key):
    if repo.find(key):
        return repo.find(key)
    return None
