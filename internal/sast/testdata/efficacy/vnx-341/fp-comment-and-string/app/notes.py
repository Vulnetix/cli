import secrets
import time

# token = str(time.time()) is guessable
HINT = "never use token = str(time.time())"


def make_token():
    return secrets.token_urlsafe(32)
