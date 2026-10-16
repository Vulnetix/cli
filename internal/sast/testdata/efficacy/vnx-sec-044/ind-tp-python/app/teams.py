import requests

~>TEAMS_HOOK = "https://acme.webhook.office.com/webhookb2/@@sample:[a-f0-9]{8}@@-@@sample:[a-f0-9]{4}@@-4@@sample:[a-f0-9]{3}@@-a@@sample:[a-f0-9]{3}@@-@@sample:[a-f0-9]{12}@@@@@sample:[a-f0-9]{8}@@-@@sample:[a-f0-9]{4}@@-4@@sample:[a-f0-9]{3}@@-b@@sample:[a-f0-9]{3}@@-@@sample:[a-f0-9]{12}@@/IncomingWebhook/@@sample:[a-f0-9]{32}@@/@@sample:[a-f0-9]{8}@@-@@sample:[a-f0-9]{4}@@-4@@sample:[a-f0-9]{3}@@-8@@sample:[a-f0-9]{3}@@-@@sample:[a-f0-9]{12}@@"


def post(text):
    requests.post(TEAMS_HOOK, json={"text": text})
