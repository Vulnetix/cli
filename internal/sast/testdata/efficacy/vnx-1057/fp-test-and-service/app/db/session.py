import sqlite3


def connect(path):
    return sqlite3.connect(path)
