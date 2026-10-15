import os
import requests

s = requests.Session()
s.cookies.set("_gitlab_session", os.environ["GITLAB_SESSION"], domain="gitlab.acme.io")
cookie = f"_gitlab_session={session_id}"
