import random
import secrets
import time

from flask import Flask, request
from django.conf import settings

from .mail import send_mail
from .models import User, db

app = Flask(__name__)
_sysrand = random.SystemRandom()


@app.route("/forgot", methods=["POST"])
def forgot_password():
    user = User.query.filter_by(email=request.form["email"]).first_or_404()
    reset_token = secrets.token_urlsafe(32)
    otp = "".join(_sysrand.choice("0123456789") for _ in range(6))
    user.reset_token = reset_token
    user.reset_token_created = time.time()
    db.session.commit()
    link = f"{settings.PUBLIC_BASE_URL}/reset/{reset_token}"
    send_mail(user.email, "Reset your password", link + " code " + otp)
    return "", 204
