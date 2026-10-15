import requests


def check():
~>    r = requests.get("https://192.168.10.5/healthz", timeout=3)
    return r.ok


def notify(payload):
    requests.post(
~>        f"http://10.1.1.30:9000/hooks/{payload['id']}",
        json=payload,
    )
