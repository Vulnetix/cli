import requests
from requests.auth import HTTPDigestAuth


def test_digest(httpbin):
    r = requests.get(httpbin("digest-auth/auth/u/p"), auth=HTTPDigestAuth("u", "p"))
    assert r.status_code == 200
