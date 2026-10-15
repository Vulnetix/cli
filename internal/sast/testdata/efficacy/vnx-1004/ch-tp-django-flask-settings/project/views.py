from flask import Flask, make_response

app = Flask(__name__)
~>app.config.update(SESSION_COOKIE_HTTPONLY=False, SESSION_COOKIE_SECURE=True)


@app.post("/login")
def login():
    resp = make_response({"ok": True})
~>    resp.set_cookie("auth_token", new_token(), secure=True, samesite="Lax")
    return resp
