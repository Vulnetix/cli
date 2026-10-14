import requests


def test_self_signed(server):
    r = requests.get(server.url, verify=False)
    assert r.status_code == 200
