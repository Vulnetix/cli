url = (f"https://{tenant}.webhook.office.com/webhookb2/{group}@{tenant_id}"
       f"/IncomingWebhook/{digest}/{connector}")
WEBHOOK = os.environ["TEAMS_WEBHOOK_URL"]
