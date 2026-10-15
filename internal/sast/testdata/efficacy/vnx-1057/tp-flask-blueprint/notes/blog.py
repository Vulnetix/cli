from flask import Blueprint, render_template, request

from notes.db import get_db

bp = Blueprint("blog", __name__)


@bp.route("/")
def index():
    db = get_db()
~>    posts = db.execute(
        "SELECT p.id, title, body FROM post p ORDER BY created DESC"
    ).fetchall()
    return render_template("blog/index.html", posts=posts)


@bp.post("/<int:post_id>/delete")
def delete(post_id):
~>    get_db().execute("DELETE FROM post WHERE id = ?", (post_id,))
    return "", 204
