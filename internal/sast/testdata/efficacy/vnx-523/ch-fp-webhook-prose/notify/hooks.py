import requests


def announce(user):
    requests.post("http://hooks.chat-vendor.com/notify", json={"text": "Password reset requested for an account"})
    requests.post(
        "http://status.partner-cdn.com/events",
        json={"event": "token rotation finished", "count": 3},
    )
