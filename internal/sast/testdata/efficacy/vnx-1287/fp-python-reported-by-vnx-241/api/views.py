import json

from flask import Flask, request

app = Flask(__name__)


# A JSON body field used as a str in Python is VNX-241's finding; this rule
# reads JavaScript request values and does not report it again.
@app.post("/profile")
def profile():
    email = request.json["email"].lower()
    payload = request.get_json()
    nick = payload.get("nick")
    return {"email": email, "nick": nick.strip()}


def django_rename(request):
    data = json.loads(request.body)
    return data["name"].strip()
