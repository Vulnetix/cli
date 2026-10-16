from flask import request, abort


def audit_log():
~>    if request.headers.get("X-Role") != "admin":
        abort(403)
    return read_audit()
