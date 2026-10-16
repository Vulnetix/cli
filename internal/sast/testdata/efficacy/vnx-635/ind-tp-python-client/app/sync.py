import subprocess

import requests


def fetch_feed(url, path):
~>    # TODO disable ssl verification only for staging
    resp = requests.get(url, verify=False, timeout=10)
~>    # FIXME: path is unsanitized, sanitize before shelling out
    subprocess.run(f"tar -xzf {path}", shell=True, check=True)
    return resp.json()


~>API_KEY = "sk-local-dev"  # HACK: hard-coded API key until vault is wired
