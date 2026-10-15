from django.conf import settings

SESSION_COOKIE_SECURE = True


def login(request, response, token, opts):
    response.set_cookie("auth_token", token, secure=True, httponly=True)
    response.set_cookie(
        "sessionid",
        token,
        secure=settings.SESSION_COOKIE_SECURE,
    )
    response.set_cookie("token", token, **opts)
