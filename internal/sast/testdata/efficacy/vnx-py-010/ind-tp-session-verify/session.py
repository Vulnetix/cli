import requests


def make_session(token):
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"
~>    session.verify = False
    return session
