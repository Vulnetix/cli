import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    try:
        conn = sqlite3.connect("app.db")
        rows = conn.execute("SELECT name FROM items WHERE name = ?", (term,)).fetchall()
    except sqlite3.Error as exc:
~>        return jsonify({"error": str(exc)}), 500
    return jsonify(rows)
