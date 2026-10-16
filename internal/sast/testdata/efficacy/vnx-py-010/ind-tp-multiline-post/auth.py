import requests


def login(user, password):
    r = requests.post(
        "https://auth.internal/token",
        data={"username": user, "password": password},
~>        verify=False,
    )
    return r.json()["token"]
