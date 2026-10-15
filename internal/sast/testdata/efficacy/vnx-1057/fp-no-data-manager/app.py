import sqlite3

from flask import Flask

app = Flask(__name__)


@app.route("/count")
def count():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM visits")
    return str(cur.fetchone()[0])
