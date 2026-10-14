import sqlite3

from flask import request


def find_user():
    name = request.args.get("name")
    con = sqlite3.connect("app.db")
    cur = con.cursor()
~>    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return cur.fetchall()


def delete_user(con, uid):
~>    con.execute(f'DELETE FROM users WHERE id = {uid}')
