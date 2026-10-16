import os
import requests
from flask import abort, request

RECAPTCHA_V3_SECRET = os.environ["RECAPTCHA_V3_SECRET"]


def verify_captcha():
    token = request.form["g-recaptcha-response"]
    r = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_V3_SECRET, "response": token},
        timeout=5,
    )
    result = r.json()
~>    if not result["success"]:
        abort(403)
