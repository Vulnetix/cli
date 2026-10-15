import hmac

import jwt
from django.contrib.auth import authenticate


def current_user(request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    claims = {}
    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256"])
~>    except Exception:
        pass
    return claims.get("sub")


def check_webhook(request):
    try:
        sig = request.headers["X-Signature"]
        expected = sign(request.body)
        hmac.compare_digest(sig, expected)
~>    except:
        pass


def login(request, username, password):
    for backend in BACKENDS:
        try:
            user = authenticate(request, username=username, password=password)
~>        except (ValueError, TypeError): continue
        if user:
            return user
