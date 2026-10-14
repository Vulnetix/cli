import requests

~>WEBHOOK = "@@sample:https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{10}/[A-Za-z0-9]{24}@@"

def notify(text):
    requests.post(WEBHOOK, json={"text": text})
