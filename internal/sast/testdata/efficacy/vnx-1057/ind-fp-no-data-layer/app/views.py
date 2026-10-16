import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/count")
def count():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM t")
    return jsonify(cur.fetchone())
