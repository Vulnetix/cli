import logging
from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)
log = logging.getLogger(__name__)

@app.route("/orders")
def orders():
    try:
        rows = fetch_orders()
    except psycopg2.Error as exc:
        log.exception("order query failed: %s", exc)
        return jsonify({"error": "internal error"}), 500
    return jsonify(rows)
