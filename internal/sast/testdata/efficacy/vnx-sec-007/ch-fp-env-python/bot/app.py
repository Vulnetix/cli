import os
from slack_sdk import WebClient

client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/your/webhook/url")
