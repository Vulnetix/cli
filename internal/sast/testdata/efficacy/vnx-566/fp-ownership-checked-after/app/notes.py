from flask import abort, jsonify, request
from flask_login import current_user

from .db import get_db


def note():
    note_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT owner_id, text FROM notes WHERE id = %s", (note_id,))
    row = cur.fetchone()
    if row is None or row[0] != current_user.id:
        abort(404)
    return jsonify(text=row[1])
