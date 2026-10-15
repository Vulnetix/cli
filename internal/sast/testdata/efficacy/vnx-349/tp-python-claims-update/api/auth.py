import jwt
from flask import request


def current_claims(key):
    claims = jwt.decode(request.headers["Authorization"][7:], key, algorithms=["HS256"])
~>    claims.update(request.get_json())
    return claims


def django_view(request, verified):
    data = request.POST.dict()
~>    verified.update(data)
    return verified
