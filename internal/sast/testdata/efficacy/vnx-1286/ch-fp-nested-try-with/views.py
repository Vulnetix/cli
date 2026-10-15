from flask import request, abort

from .db import session_scope


def update_qty():
    try:
        with session_scope() as s:
            qty = int(request.form["qty"])
            s.execute("UPDATE cart SET qty = :q", {"q": qty})
    except (KeyError, ValueError):
        abort(400)
    return "", 204
