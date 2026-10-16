import random
import time
from random import choice
import string

from flask import Flask, request, url_for

from .mail import send_mail
from .models import User, db

app = Flask(__name__)


@app.route("/forgot", methods=["POST"])
def forgot_password():
    user = User.query.filter_by(email=request.form["email"]).first_or_404()
~>    reset_token = str(random.randint(100000, 999999))
    user.reset_token = reset_token
    user.reset_token_created = time.time()
    db.session.commit()
~>    link = f"http://{request.host}/reset/{reset_token}"
    send_mail(user.email, "Reset your password", link)
    return "", 204


def temp_password():
~>    temporary_password = "".join(choice(string.ascii_letters) for _ in range(10))
    return temporary_password
