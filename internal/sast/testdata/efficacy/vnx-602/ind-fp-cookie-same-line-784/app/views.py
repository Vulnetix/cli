from flask import abort, request


def admin_panel():
    if request.cookies.get("admin") == "1":
        return "panel"
    abort(403)
