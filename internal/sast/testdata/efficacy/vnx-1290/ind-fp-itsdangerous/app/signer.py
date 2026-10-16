import base64
from flask import request
from itsdangerous import URLSafeSerializer

s = URLSafeSerializer("secret")


def user():
    token = request.cookies.get("auth")
    return s.loads(token)
