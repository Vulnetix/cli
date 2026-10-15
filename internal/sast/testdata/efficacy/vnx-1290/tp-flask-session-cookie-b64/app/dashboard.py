import base64

from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/dashboard")
def dashboard():
    session_token = request.cookies.get("session")
    if not session_token:
        return redirect("/login")
~>    username = base64.b64decode(session_token).decode().split(":")[0]
    return f"hello {username}"
