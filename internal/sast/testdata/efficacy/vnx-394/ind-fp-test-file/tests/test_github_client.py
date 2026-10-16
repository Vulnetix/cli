import requests


def test_live_repos_endpoint():
    r = requests.get("https://api.github.com/orgs/python/repos", timeout=10)
    assert isinstance(r.json(), list)
