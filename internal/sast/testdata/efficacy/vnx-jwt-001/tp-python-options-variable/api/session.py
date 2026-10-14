from jose import jwt

~>UNVERIFIED = {"verify_signature": False}


def read_session(request):
    token = request.headers.get("X-Session")
    return jwt.decode(token, key=None, options=UNVERIFIED)
