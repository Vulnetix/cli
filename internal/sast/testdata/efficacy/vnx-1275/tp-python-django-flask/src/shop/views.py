from flask import Flask, make_response

app = Flask(__name__)
~>app.config["SESSION_COOKIE_SAMESITE"] = "None"
~>app.config.update(REMEMBER_COOKIE_SAMESITE=None)


def login(user):
    resp = make_response("ok")
~>    resp.set_cookie("userid", user.id, max_age=3600, samesite=None, secure=True)
    resp.set_cookie(
        "session",
        user.token,
~>        samesite="None",
    )
    return resp
