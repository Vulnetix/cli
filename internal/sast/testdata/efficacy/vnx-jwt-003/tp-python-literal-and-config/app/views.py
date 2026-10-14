import jwt
from flask import Flask

app = Flask(__name__)
~>app.config["JWT_SECRET_KEY"] = 'dvga'
~>JWT_SECRET = "f9a1c0de-local"


def issue(username):
~>    return jwt.encode({"username": username}, 'csrf_vulneribility', algorithm='HS256')


def read(cookie):
~>    return jwt.decode(cookie, key="csrf_vulneribility", algorithms=['HS256'])
