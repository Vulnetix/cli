import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
def show(order_id):
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
~>    cur.execute("SELECT id, total FROM orders WHERE id = ?", (order_id,))
    return jsonify(cur.fetchone())
