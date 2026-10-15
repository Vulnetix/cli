from flask import request


def audit_address():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded and "," in forwarded:
        return forwarded.split(",")[0].strip()
    if request.remote_addr == "127.0.0.1":
        return "local"
    return forwarded or request.remote_addr
