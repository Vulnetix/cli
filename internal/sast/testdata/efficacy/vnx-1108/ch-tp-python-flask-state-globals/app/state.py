import sqlite3

_conn = None
_cache = {}
_hits = 0


def connect(path):
~>    global _conn
    _conn = sqlite3.connect(path)


def remember(key, value):
~>    global _cache, _hits
    _hits += 1
    _cache[key] = value


def reset():
~>    global _conn, _cache, _hits
    _conn = None
    _cache = {}
    _hits = 0
