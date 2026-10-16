from flask import abort, jsonify, request
from flask_login import current_user, login_required

from .db import get_db
from .web import app


@app.route("/messages/read")
@login_required
def read_message():
    message_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT recipient_id, subject, body FROM messages WHERE id = %s", (message_id,))
    row = cur.fetchone()
    if row is None or row[0] != current_user.id:
        abort(404)
    return jsonify(subject=row[1], body=row[2])
