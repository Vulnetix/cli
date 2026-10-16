import random

from svc.issuer import TokenIssuer


def test_tokens_increase():
    issuer = TokenIssuer(0)
    last_token = issuer.issue()
    token = last_token + random.randint(1, 10)
    assert token > last_token
