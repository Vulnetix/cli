from flask import g, request


def load_user():
    token = request.headers.get("Authorization", "")
    g.user = verify_jwt(token.removeprefix("Bearer "))
    g.theme = request.cookies.get("role_theme_preference", "light")
    g.request_id = request.headers.get("X-Request-Id")
    g.is_admin = g.user is not None and g.user.role == "admin"
