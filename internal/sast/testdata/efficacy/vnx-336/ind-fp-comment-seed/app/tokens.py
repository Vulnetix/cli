import secrets

# Previously this module called random.seed(1337) and then used random.choice
# for the token; that was replaced with the secrets module.
HELP_TEXT = "never call random.seed(42) before generating a password"


def generate_password(length=20):
    return secrets.token_urlsafe(length)
