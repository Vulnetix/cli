from flask import Blueprint, request, redirect

from .db import get_db

bp = Blueprint("comments", __name__)


@bp.route("/comments/delete", methods=["POST"])
def delete_comment():
    comment_id = request.form["comment_id"]
    db = get_db()
~>    db.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    db.commit()
    return redirect("/")
