import requests

~>cookies = {"_gitlab_session": "@@sample:[0-9a-f]{32}@@"}
resp = requests.get("https://gitlab.acme-corp.io/dashboard", cookies=cookies)
