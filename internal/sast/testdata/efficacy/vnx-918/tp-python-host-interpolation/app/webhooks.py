import httpx
import requests
from flask import request


def ping():
    host = request.json["host"]
~>    httpx.post(f"http://{host}/hook", json={"ok": True})
~>    requests.get("http://" + host + "/status")
    base = request.form.get("callback")
    full = base + "/notify"
~>    requests.request("POST", full, data="x")
    import urllib.request
~>    urllib.request.urlopen(
        request.values["feed"])
