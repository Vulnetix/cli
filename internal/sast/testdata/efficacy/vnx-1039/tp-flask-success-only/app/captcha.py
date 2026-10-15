import requests
from flask import request, abort

VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def require_human():
    token = request.form.get("g-recaptcha-response")
    r = requests.post(VERIFY_URL, data={"secret": SECRET, "response": token}, timeout=5)
    result = r.json()
~>    if not result["success"]:
        abort(403)
