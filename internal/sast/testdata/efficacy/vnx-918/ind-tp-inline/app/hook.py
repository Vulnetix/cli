import requests
from flask import request

def notify():
~>    r = requests.post(request.form.get("callback"), json={"done": True})
    return r.status_code
