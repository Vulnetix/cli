import requests

s = requests.Session()
~>s.cookies.set("_gitlab_session", "@@sample:[0-9a-f]{32}@@", domain="gitlab.acme.io")
