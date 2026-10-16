from flask import Blueprint, redirect, request, url_for

bp = Blueprint("auth", __name__)


@bp.route("/login/done")
def login_done():
    next_url = request.args.get("next", "")
    if next_url.startswith("https://app.example.com"):
~>        return redirect(next_url)
    return redirect(url_for("dashboard.index"))
