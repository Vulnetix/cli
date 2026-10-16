import sqlite3
from flask import Blueprint, jsonify

bp = Blueprint("reports", __name__)


@bp.route("/reports/daily")
def daily():
~>    db = sqlite3.connect("app.db")
    rows = db.execute("SELECT day, n FROM daily").fetchall()
    return jsonify(rows)
