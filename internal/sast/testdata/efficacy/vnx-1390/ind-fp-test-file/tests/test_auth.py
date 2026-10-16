from requests.auth import HTTPDigestAuth

def test_digest(server):
    r = requests.get(server.url, auth=HTTPDigestAuth("u", "p"))
    assert r.status_code == 200
