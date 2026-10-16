import requests

RECAPTCHA_V3_SECRET = "from-env"


def is_human(token):
    data = requests.post("https://www.google.com/recaptcha/api/siteverify",
                         data={"secret": RECAPTCHA_V3_SECRET, "response": token}).json()
    if not data["success"]:
        return False
    return data["score"] >= 0.5 and data["action"] == "login"
