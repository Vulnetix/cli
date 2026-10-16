from flask import Blueprint, request, jsonify
import sqlite3

bp = Blueprint("users", __name__)


@bp.get("/users/<int:uid>")
def user(uid):
~>    conn = sqlite3.connect("app.db")
~>    cur = conn.cursor()
~>    cur.execute("SELECT name FROM users WHERE id = ?", (uid,))
    return jsonify(cur.fetchone())
