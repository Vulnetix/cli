from flask import Blueprint, request, make_response, abort, render_template

bp = Blueprint("admin", __name__)


@bp.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    resp = make_response(render_template("home.html"))
~>    resp.set_cookie("is_admin", "1" if user.admin else "0", max_age=3600)
~>    resp.set_cookie(key="access_level", value=str(user.level))
    resp.set_cookie("locale", user.locale)
    return resp


@bp.route("/admin")
def admin_panel():
~>    if request.cookies.get("is_admin") != "1":
        abort(403)
    return render_template("admin.html")
