import requests
~>cookies = {"_gitlab_session": "@@sample:[a-f0-9]{32}@@"}
r = requests.get("https://gitlab.acme-corp.io/", cookies=cookies)
