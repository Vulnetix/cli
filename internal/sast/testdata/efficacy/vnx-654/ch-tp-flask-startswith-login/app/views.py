from flask import request, redirect
from flask_login import login_user

from .models import User


@app.route("/kiosk")
def kiosk():
~>    if request.remote_addr.startswith("192.168.10."):
        login_user(User.query.get(1))
        return redirect("/")
    return redirect("/login")
