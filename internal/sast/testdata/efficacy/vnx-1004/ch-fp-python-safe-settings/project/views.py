from flask import make_response


def login():
    resp = make_response({"ok": True})
    resp.set_cookie(
        "session",
        new_session(),
        secure=True,
        httponly=True,
    )
    resp.set_cookie("theme", "dark")
    return resp
