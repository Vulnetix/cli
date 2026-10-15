import jwt


def current_user(request):
    token = request.headers["Authorization"].split()[1]
    claims = jwt.decode(
        token,
        algorithms=["HS256"],
~>        options={"verify_signature": False},
    )
    return claims["sub"]
