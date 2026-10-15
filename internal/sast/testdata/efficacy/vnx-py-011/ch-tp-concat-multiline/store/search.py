import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    name = request.args.get("name", "")
    conn = sqlite3.connect("store.db")
    cur = conn.cursor()
~>    cur.execute(
        "SELECT id, title FROM products WHERE title LIKE '%" + name + "%'"
    )
    return {"rows": cur.fetchall()}
