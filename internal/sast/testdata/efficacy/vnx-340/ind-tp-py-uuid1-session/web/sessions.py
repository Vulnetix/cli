import uuid

from flask import make_response


def login_response(user):
~>    session_id = uuid.uuid1().hex
    store.save(session_id, user.id)
    resp = make_response({"ok": True})
    resp.set_cookie("sid", session_id, httponly=True, secure=True)
    return resp
