import requests


def send(to, subject, text):
    return requests.post(
        "https://api.mailgun.net/v3/mg.acme.example/messages",
~>        auth=("api", "key-@@sample:[0-9a-z]{32}@@"),
        data={"from": "noreply@acme.example", "to": to, "subject": subject, "text": text},
    )
