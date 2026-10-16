import os

import requests


class BillingConfigError(RuntimeError):
    pass


def client_from_env():
    api_key = os.environ.get("STRIPE_API_KEY", "")
    if not api_key.startswith("sk_"):
~>        raise BillingConfigError(f"STRIPE_API_KEY does not look like a secret key: {api_key}")
    session = requests.Session()
    session.auth = (api_key, "")
    return session
