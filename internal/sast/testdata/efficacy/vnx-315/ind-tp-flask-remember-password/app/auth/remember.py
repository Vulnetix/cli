from flask import make_response, redirect, request


def login_submit():
    resp = make_response(redirect("/"))
    if request.form.get("remember"):
~>        resp.set_cookie("saved_password", request.form["password"], max_age=30 * 86400)
    return resp
