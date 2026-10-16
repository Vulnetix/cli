from flask import Flask, make_response

app = Flask(__name__)
# Reported by VNX-614 (a cookie without Secure), not by this rule.
app.config["SESSION_COOKIE_SECURE"] = False
# Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
app.config.update(SESSION_COOKIE_HTTPONLY=False)


@app.route("/login", methods=["POST"])
def login():
    response = make_response("ok")
    # Reported by VNX-614 (a cookie without Secure), not by this rule.
    response.set_cookie("session_id", token, max_age=3600, secure=False)
    response.set_cookie(
        "remember_token",
        token,
~>        httponly=False,
    )
    return response
