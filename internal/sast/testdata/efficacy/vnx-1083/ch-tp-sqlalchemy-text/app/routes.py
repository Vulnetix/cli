from flask import Blueprint, request
from sqlalchemy import text

from .extensions import db

bp = Blueprint("reports", __name__)


@bp.route("/reports")
def reports():
    year = request.args.get("year")
~>    rows = db.session.execute(text("SELECT * FROM sales WHERE year = :y"), {"y": year})
~>    total = db.engine.execute("SELECT sum(amount) FROM sales").scalar()
    return {"rows": [dict(r) for r in rows], "total": total}


@bp.route("/search")
def search():
    term = request.args.get("q", "")
~>    posts = Post.query.filter(text("title = '%s'" % term)).all()
    ordered = Post.query.order_by(Post.created.desc()).all()
    return {"posts": [p.id for p in posts], "n": len(ordered)}
