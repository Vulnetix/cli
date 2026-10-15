import sqlite3
import psycopg2

from flask import Blueprint, jsonify

bp = Blueprint("reports", __name__)


@bp.route("/reports/daily")
def daily():
~>    db = sqlite3.connect("app.db")
    rows = db.execute("SELECT day, total FROM daily").fetchall()
    return jsonify(rows)


@bp.route("/reports/warehouse")
def warehouse():
~>    conn = psycopg2.connect(dsn="dbname=wh")
    return jsonify([])
