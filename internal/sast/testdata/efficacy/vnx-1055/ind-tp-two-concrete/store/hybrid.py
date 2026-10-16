import sqlite3


class FileStore:
    def __init__(self, path):
        self.path = path

    def read(self):
        with open(self.path) as fh:
            return fh.read()


class SqlStore:
    def __init__(self, dsn):
        self.conn = sqlite3.connect(dsn)

    def query(self, q):
        return self.conn.execute(q)


~>class HybridStore(FileStore, SqlStore):
    def __init__(self, path, dsn):
        FileStore.__init__(self, path)
        SqlStore.__init__(self, dsn)
