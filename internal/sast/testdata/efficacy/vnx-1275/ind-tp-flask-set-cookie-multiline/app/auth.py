from flask import make_response


def login(user):
    resp = make_response("ok")
    resp.set_cookie(
        "userid",
        str(user.id),
        secure=True,
~>        samesite=None,
    )
    return resp
