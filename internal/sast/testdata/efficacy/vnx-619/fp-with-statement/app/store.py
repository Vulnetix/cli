import sqlite3
from django.db import connection


def find_user(conn, user_id):
    with conn.cursor() as cur:
        cur.execute("SELECT name FROM users WHERE id = ?", (user_id,))
        return cur.fetchone()


def report():
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        return cursor.fetchall()


def legacy(conn):
    cur = conn.cursor()
    with cur:
        cur.execute("SELECT 1")
