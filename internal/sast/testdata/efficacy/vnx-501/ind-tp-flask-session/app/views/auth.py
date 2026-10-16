from flask import Blueprint, redirect, request, session, url_for

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET"])
def login_form():
~>    session["next_url"] = request.args.get("next")
    return redirect(url_for("auth.show"))


@bp.route("/prefs", methods=["POST"])
def save_prefs():
    lang = request.form.get("lang", "en")
    chosen = lang.lower()
~>    session["lang"] = chosen
    theme = request.cookies.get("theme")
~>    session.update(theme=theme)
    return redirect("/")
