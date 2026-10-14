import jwt


def issue(user, key):
    return jwt.encode(
~>        {"sub": user.id, "password": user.password, "exp": expiry()},
        key,
        algorithm="HS256",
    )


def issue_card(user, key):
    payload = {"sub": user.id, "exp": expiry()}
~>    payload["credit_card"] = user.card_number
    return jwt.encode(payload, key, algorithm="HS256")
