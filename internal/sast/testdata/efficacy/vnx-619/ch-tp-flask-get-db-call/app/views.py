from flask import Blueprint, g, jsonify
import sqlite3

bp = Blueprint("items", __name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect("app.db")
    return g.db


@bp.route("/items")
def list_items():
~>    cur = get_db().cursor()
    cur.execute("SELECT id, name FROM items")
    rows = cur.fetchall()
    return jsonify(rows)
