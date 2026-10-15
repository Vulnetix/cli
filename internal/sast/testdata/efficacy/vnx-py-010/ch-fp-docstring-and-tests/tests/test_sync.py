import requests


def test_local_server(live_server):
    r = requests.get(live_server.url, verify=False)
    assert r.status_code == 200
