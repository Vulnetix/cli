import os
import pytest

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


def test_callback_flow(client):
    os.environ["GIT_SSL_NO_VERIFY"] = "1"
    assert client.get("/cb").status_code == 200
