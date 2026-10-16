import os, requests
requests.post("https://api.mailgun.net/v3/x/messages", auth=("api", os.environ["MAILGUN_API_KEY"]))
