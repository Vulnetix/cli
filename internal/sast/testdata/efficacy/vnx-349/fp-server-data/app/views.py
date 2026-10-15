from flask import request


def principal(claims, defaults):
    claims.update(defaults)
    payload = {**request.json}
    body = dict(request.json)
    claims.update({"locale": request.form.get("locale", "en")})
    return claims
