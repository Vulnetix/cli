import secrets

# Old code: random.seed(len(username)) then random.getrandbits(64) for the token.
# That gave one token per username length; the secrets module replaced it.


def generate_reset_token():
    return secrets.token_urlsafe(32)
