from flask import make_response, request


def remember_me():
    resp = make_response("ok")
~>    resp.set_cookie("password", request.form["password"], max_age=86400)
~>    resp.set_cookie("remember", f"{request.form['user']}:{request.form['password']}")
    resp.set_cookie("theme", "dark")
    return resp
