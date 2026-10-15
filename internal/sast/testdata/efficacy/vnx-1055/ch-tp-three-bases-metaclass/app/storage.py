class Registry(type):
    pass


class FileStore:
    def __init__(self, root):
        self.root = root

    def save(self, key, data):
        open(self.root + key, "wb").write(data)


class CacheStore:
    def __init__(self):
        self.items = {}

    def save(self, key, data):
        self.items[key] = data


class AuditLog:
    entries = []


~>class TieredStore(FileStore, CacheStore, AuditLog, metaclass=Registry):
    pass
