import jwt


def current_user(token):
    payload = jwt.decode(token,
                         SECRET_KEY,
~>                         verify=False)
    return payload["sub"]
