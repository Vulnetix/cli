from flask import make_response
from flask_login import login_required, current_user


@app.route("/account")
@login_required
~>@cache.cached(timeout=120)
def account():
    return render_template("account.html", user=current_user)


@app.route("/api/me")
@login_required
def me():
    resp = make_response(jsonify(email=current_user.email))
~>    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp
