import requests


def test_login_page():
    # TODO: disable ssl verification for the local self-signed server
    r = requests.get("https://localhost:8443/login", verify=False)
    assert r.status_code == 200
