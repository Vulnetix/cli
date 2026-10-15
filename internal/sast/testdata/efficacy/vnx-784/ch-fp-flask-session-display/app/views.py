from flask import request, session, render_template


def profile():
    if session.get("is_admin"):
        return render_template("admin.html")
    return render_template("profile.html", role=request.cookies.get("role"))
