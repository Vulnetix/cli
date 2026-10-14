import jwt


def current_user(request):
    token = request.headers["Authorization"].split()[1]
~>    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def current_tenant(request):
    raw = request.cookies.get("session")
    payload = jwt.decode(
        raw,
        settings.JWT_KEY,
        algorithms=["HS256"],
~>        options={'verify_signature' : False, "verify_exp": True},
    )
    return payload["tenant"]
