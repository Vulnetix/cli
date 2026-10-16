import hmac
import secrets

AGENT_SECRET = load_agent_secret()


def answer(challenge):
~>    return hmac.digest(AGENT_SECRET, challenge, "sha256")


def issue_challenge():
    return secrets.token_bytes(16)


def check(nonce, reply):
    expected = hmac.digest(AGENT_SECRET, nonce, "sha256")
    return hmac.compare_digest(expected, reply)
