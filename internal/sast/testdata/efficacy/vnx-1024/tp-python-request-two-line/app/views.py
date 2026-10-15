from flask import request


def admin_panel():
    role = request.args.get("role")
~>    if role == 1:
        return grant()
~>    if request.cookies.get("is_admin") == 1:
        return grant()
    return deny()
