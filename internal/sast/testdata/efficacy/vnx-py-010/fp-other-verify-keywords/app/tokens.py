import jwt
import requests


def claims(url):
    r = requests.get(url, timeout=5)
    data = jwt.decode(r.text, "secret", verify=False)
    form = SignupForm(r.json())
    form.validate(verify=False)
    return data
