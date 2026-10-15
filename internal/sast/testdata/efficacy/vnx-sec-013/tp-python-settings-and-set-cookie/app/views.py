from flask import Flask, make_response

app = Flask(__name__)
~>app.config["SESSION_COOKIE_SECURE"] = False
~>app.config.update(SESSION_COOKIE_HTTPONLY=False)


@app.route("/login", methods=["POST"])
def login():
    response = make_response("ok")
~>    response.set_cookie("session_id", token, max_age=3600, secure=False)
    response.set_cookie(
        "remember_token",
        token,
~>        httponly=False,
    )
    return response
