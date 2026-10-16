import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def db():
    return sqlite3.connect("notes.db")


@app.route("/notes/archive", methods=["POST"])
def archive_note():
    note_id = request.form["note_id"]
    conn = db()
    cur = conn.cursor()
~>    cur.execute("UPDATE notes SET archived = 1 WHERE id = ?", (note_id,))
    conn.commit()
    return jsonify(ok=True)
