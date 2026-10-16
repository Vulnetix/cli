import os
import requests

user = os.environ["ARTIFACT_USER"]
password = os.environ["ARTIFACT_PASSWORD"]
url = f"https://{user}:{password}@nexus.acme-corp.io/repository/raw/build.tgz"
other = "https://ci:${GIT_TOKEN}@git.acme-corp.io/x.git"
third = "https://ci:%s@git.acme-corp.io/x.git" % password
fourth = "https://ci:" + password + "@git.acme-corp.io/x.git"
resp = requests.get(url)
