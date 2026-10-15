from flask_login import login_required


@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    return render_template("admin.html", path=request.path)
