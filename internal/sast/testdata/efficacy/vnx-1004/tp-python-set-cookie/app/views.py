from flask import Flask, make_response

app = Flask(__name__)
~>app.config["SESSION_COOKIE_HTTPONLY"] = False


@app.route("/login", methods=["POST"])
def login():
    token = issue_token()
    resp = make_response("ok")
~>    resp.set_cookie("session_id", token)
~>    resp.set_cookie(key="auth_token", value=token, secure=True)
~>    resp.set_cookie(
        "userid",
        str(42),
        max_age=3600,
    )
    return resp
