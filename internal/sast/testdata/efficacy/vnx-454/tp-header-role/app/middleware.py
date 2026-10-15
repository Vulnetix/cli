from flask import request, g


def attach_role():
~>    g.user_role = request.headers.get("X-User-Role", "viewer")
~>    level = request.META.get("HTTP_X_ACCESS_LEVEL")
    return level
