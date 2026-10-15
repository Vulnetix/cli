import sqlite3

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
    return g.db


def list_posts():
    return get_db().execute("SELECT id, title FROM post").fetchall()
