from flask import request


def find(cursor):
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cursor.fetchall()
