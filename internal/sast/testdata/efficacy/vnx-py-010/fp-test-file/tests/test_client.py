import requests


def test_self_signed_dev_server(local_server):
    r = requests.get(local_server.url, verify=False)
    assert r.status_code == 200
