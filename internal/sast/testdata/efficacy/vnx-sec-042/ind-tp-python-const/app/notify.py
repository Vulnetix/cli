import requests

~>SLACK_URL = "https://hooks.slack.com/services/T@@sample:[A-Z0-9]{9}@@/B@@sample:[A-Z0-9]{10}@@/@@sample:[A-Za-z0-9]{24}@@"


def alert(msg):
    requests.post(SLACK_URL, json={"text": msg}, timeout=5)
