import json
import sqlite3


class FileStore:
    def __init__(self, path):
        self.path = path
        self.cache = {}

    def save(self, key, value):
        with open(self.path, "w") as fh:
            json.dump({key: value}, fh)


class SqlStore:
    def __init__(self, dsn):
        self.conn = sqlite3.connect(dsn)
        self.cache = []

    def save(self, key, value):
        self.conn.execute("INSERT INTO kv VALUES (?, ?)", (key, value))


~>class HybridStore(FileStore, SqlStore):
    def __init__(self, path, dsn):
        FileStore.__init__(self, path)
        SqlStore.__init__(self, dsn)
