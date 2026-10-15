import os

user = os.environ["NEXUS_USER"]
password = os.environ["NEXUS_PASSWORD"]
url = f"https://{user}:{password}@nexus.acme-corp.io/repository/raw/"
legacy = "https://%s:%s@%s/simple/" % (user, password, "pypi.acme-corp.io")
remote = "https://${GIT_USER}:${GIT_TOKEN}@git.acme-corp.io/platform/infra.git"
shell = "https://$CI_USER:$CI_TOKEN@git.acme-corp.io/platform/infra.git"
joined = "https://" + user + ":" + password + "@nexus.acme-corp.io/"
