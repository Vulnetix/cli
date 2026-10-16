from flask import Flask, make_response, jsonify

app = Flask(__name__)
~>app.config["SESSION_COOKIE_SECURE"] = False


@app.route("/login", methods=["POST"])
def login():
    token = issue_token()
    resp = make_response(jsonify(ok=True))
~>    resp.set_cookie("auth_token", token, httponly=True)
    return resp


def issue_token():
    return "t"
