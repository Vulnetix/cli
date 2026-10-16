import requests


def test_local_stub(httpserver):
    resp = requests.get(httpserver.url_for("/health"), verify=False)
    assert resp.status_code == 200
