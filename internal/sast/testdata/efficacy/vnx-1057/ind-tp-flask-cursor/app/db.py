import sqlite3
def get_db():
    return sqlite3.connect("x.db")
