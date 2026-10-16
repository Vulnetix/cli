from flask import Blueprint, url_for
from authlib.integrations.flask_client import OAuth

bp = Blueprint("login", __name__)
oauth = OAuth()
github = oauth.register("github")


@bp.route("/login")
def login():
    redirect_uri = url_for("login.callback", _external=True)
~>    return github.authorize_redirect(redirect_uri, state="static-csrf-token")
