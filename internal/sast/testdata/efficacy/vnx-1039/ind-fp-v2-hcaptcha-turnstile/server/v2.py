import requests

def verify_v2(token, secret):
    r = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": secret, "response": token})
    return r.json()["success"]

def verify_hcaptcha(token, secret):
    r = requests.post("https://hcaptcha.com/siteverify", data={"secret": secret, "response": token})
    result = r.json()
    if not result["success"]:
        raise PermissionError("captcha")

def verify_turnstile(token, secret):
    r = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data={"secret": secret, "response": token})
    return r.json()["success"]
