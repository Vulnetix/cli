import jwt
import requests


def fetch_jwks(url):
    resp = requests.get(url,
                        timeout=5,
                        verify=False)
    return resp.json()


def decode(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_exp": False})
