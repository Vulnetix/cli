import re

from flask import Blueprint, request, render_template

from .models import Comment, db

bp = Blueprint("comments", __name__)

~>SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.S)


def clean_name(raw):
~>    return raw.replace("<script>", "").replace("</script>", "")


@bp.route("/comments", methods=["POST"])
def add_comment():
    author = clean_name(request.form.get("author", ""))
    body = request.form.get("body", "")
~>    body = re.sub(r"onerror\s*=", "", body)
    comment = Comment(author=author, body=SCRIPT_RE.sub("", body))
    db.session.add(comment)
    db.session.commit()
    return render_template("comment.html", comment=comment)
