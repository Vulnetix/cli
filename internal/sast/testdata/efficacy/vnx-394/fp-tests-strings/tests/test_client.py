import requests


def test_live():
    r = requests.get("http://localhost:8000/health")
    assert r.json() == {"ok": True}
