import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/notes")
def create_note():
    payload = request.get_json()
    try:
        with sqlite3.connect("notes.db") as db:
            db.execute("INSERT INTO notes (body) VALUES (?)", (payload["body"],))
    except sqlite3.Error as exc:
~>        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True}), 201
