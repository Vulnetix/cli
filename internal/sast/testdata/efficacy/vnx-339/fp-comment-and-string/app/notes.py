import secrets

# random.seed(len(username)) leaves only a few hundred possible tokens
NOTE = "never use random.seed(len(name)) for a reset token"


def make_reset_token():
    return secrets.token_hex(16)
