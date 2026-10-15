from flask import Blueprint, abort, g, request

from .db import get_db

bp = Blueprint("drafts", __name__)


@bp.route("/drafts/view")
def view_draft():
    draft_id = request.args.get("id")
    row = get_db().execute(
        "SELECT id, author_id, body FROM drafts WHERE id = ?", (draft_id,)
    ).fetchone()
    if row is None:
        abort(404)
    if row["author_id"] != g.user["id"]:
        abort(403)
    return {"body": row["body"]}
