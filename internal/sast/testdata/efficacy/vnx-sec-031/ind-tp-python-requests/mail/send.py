import requests

def send(to, body):
    return requests.post(
        "https://api.mailgun.net/v3/mg.example.com/messages",
~>        auth=("api", "key-@@sample:[0-9a-z]{32}@@"),
        data={"to": to, "text": body},
    )
