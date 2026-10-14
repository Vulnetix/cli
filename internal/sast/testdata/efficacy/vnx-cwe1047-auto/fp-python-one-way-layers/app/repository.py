import sqlite3

from .models import User


def save(user: User) -> User:
    with sqlite3.connect("app.db") as conn:
        conn.execute("INSERT INTO users(name) VALUES (?)", (user.name,))
    return user
