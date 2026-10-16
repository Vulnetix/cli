SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Strict"


class Response:
    def set_cookie(self, key, value="", samesite=None, secure=False):
        self.cookies[key] = (value, samesite, secure)


def issue(resp, uid):
    resp.set_cookie("uid", uid, samesite="Lax", secure=True)
    return resp
