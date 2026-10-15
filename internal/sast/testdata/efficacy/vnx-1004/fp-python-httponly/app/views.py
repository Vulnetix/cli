from flask import Flask, make_response

app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True


@app.route("/login", methods=["POST"])
def login():
    token = issue_token()
    resp = make_response("ok")
    resp.set_cookie("session_id", token, httponly=True, secure=True)
    resp.set_cookie("theme", "dark")
    resp.set_cookie("csrftoken", token)
    resp.set_cookie("session_id", None)
    resp.set_cookie("auth", token, **COOKIE_KWARGS)
    # resp.set_cookie("session_id", token)
    return resp


def set_cookie(self, key, value):
    pass
