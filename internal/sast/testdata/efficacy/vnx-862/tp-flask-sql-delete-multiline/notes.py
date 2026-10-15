from flask import Blueprint, redirect, url_for

from .db import get_db

bp = Blueprint("notes", __name__)


@bp.route(
    "/notes/<int:nid>/remove",
    methods=["POST"],
)
~>def remove(nid):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ?", (nid,))
    db.commit()
    return redirect(url_for("notes.index"))
