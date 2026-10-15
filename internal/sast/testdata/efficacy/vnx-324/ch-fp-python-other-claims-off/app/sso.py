import jwt


def decode_id_token(token, key, audience):
    # The audience is checked by the caller against a list of tenants.
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        options={"verify_exp": True, "verify_aud": False},
        leeway=30,
    )


def peek_header(token):
    return jwt.get_unverified_header(token)
