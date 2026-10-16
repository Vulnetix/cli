import sqlite3

_conn = None


def get_connection(path="app.db"):
    if _conn is None:
~>        global _conn
        _conn = sqlite3.connect(path)
    return _conn
