from flask import request, abort


def admin_panel():
~>    if request.cookies.get("is_admin") == "1":
        return render_admin()
    abort(403)
