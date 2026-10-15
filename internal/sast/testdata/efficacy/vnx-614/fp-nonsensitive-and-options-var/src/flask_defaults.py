default_config = {
    "SESSION_COOKIE_SECURE": False,
    "SESSION_COOKIE_HTTPONLY": True,
}


def keep(response, name, value, secure):
    response.set_cookie(name, value, secure=secure)
    response.set_cookie("locale", "en")
