from flask import abort, request


def register():
    if request.args.get("role") == "admin":
        abort(403)
    if request.cookies.get("is_admin"):
        raise PermissionError("admin cannot be requested")
    return create_user(request.form)
