import sqlite3

from flask import g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("shop.sqlite")
    return g.db
