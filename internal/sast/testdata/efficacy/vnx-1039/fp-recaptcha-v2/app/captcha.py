import requests
from flask import request, abort


def require_human():
    token = request.form.get("g-recaptcha-response")
    result = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": SECRET, "response": token},
    ).json()
    if not result["success"]:
        abort(403)
