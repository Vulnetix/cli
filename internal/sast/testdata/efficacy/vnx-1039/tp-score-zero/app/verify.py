import requests

RECAPTCHA_V3_SECRET = "configured-elsewhere"


def is_human(token):
    data = requests.post(
        "https://www.google.com/recaptcha/api/siteverify",
        data={"secret": RECAPTCHA_V3_SECRET, "response": token},
    ).json()
~>    return data.get("success") and data.get("score", 0) >= 0.0
