import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def test_callback(client):
    assert client.get("/callback").status_code == 302
