import os
WEBHOOK = os.environ["SLACK_WEBHOOK_URL"]
BASE = "https://hooks.slack.com/services/"
url = f"https://hooks.slack.com/services/{team}/{bot}/{secret}"
