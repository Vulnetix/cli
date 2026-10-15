import requests


def test_login(password):
    requests.post("http://auth.acme-corp.com/login", data={"password": password})
