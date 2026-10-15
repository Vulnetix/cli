import requests


def send(to, text):
    return requests.post(
        "https://api.mailgun.net/v3/mg.acme.example/messages",
~>        auth=("api", "@@sample:[a-f0-9]{32}@@-@@sample:[a-f0-9]{8}@@-@@sample:[a-f0-9]{8}@@"),
        data={"from": "ops@acme.example", "to": to, "text": text},
    )
