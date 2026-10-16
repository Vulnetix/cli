import os


def test_callback_over_http(client):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    resp = client.get("/login/callback?code=abc")
    assert resp.status_code == 302
