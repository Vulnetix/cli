from pathlib import Path

import requests


def fetch_and_cache_token(client_id, client_secret):
    resp = requests.post(
        "https://auth.internal.example/oauth/token",
        data={"grant_type": "client_credentials"},
        auth=(client_id, client_secret),
        timeout=10,
    )
    resp.raise_for_status()
    access_token = resp.json()["access_token"]
~>    Path("/tmp/svc_access_token").write_text(access_token)
    return access_token
