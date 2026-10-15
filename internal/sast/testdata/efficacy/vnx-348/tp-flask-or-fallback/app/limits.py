from flask import request


def requester():
~>    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr


def real_ip():
~>    ip = request.headers.get("X-Real-IP") or request.environ.get("REMOTE_ADDR")
    return ip
