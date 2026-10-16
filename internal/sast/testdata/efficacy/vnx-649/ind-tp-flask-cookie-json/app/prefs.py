import base64
import json

from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/account")
def account():
~>    profile = json.loads(base64.b64decode(request.cookies.get("profile", "e30=")))
    return render_template("account.html", plan=profile.get("plan"), role=profile.get("role"))
