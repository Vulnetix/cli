from flask import Response

SESSION_COOKIE = "sid"


~>def set_auth_cookie(resp: Response, token: str, max_age: int = 3600, httponly: bool = False) -> Response:
    resp.set_cookie(SESSION_COOKIE, token, max_age=max_age, httponly=httponly, secure=True, samesite="Lax")
    return resp
