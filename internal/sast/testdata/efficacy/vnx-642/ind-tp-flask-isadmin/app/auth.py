from flask import make_response, redirect

def finish_login(user):
    resp = make_response(redirect("/home"))
~>    resp.set_cookie("is_admin", "1" if user.admin else "0", httponly=True)
    return resp
