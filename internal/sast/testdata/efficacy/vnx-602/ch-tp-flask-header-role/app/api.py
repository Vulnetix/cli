from flask import request, abort


def export_all():
~>    if request.headers.get("X-Role") == "admin":
        return dump()
    abort(403)
