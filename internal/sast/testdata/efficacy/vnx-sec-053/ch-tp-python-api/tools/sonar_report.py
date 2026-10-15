import requests

~>SONAR_TOKEN = "squ_@@sample:[0-9a-f]{40}@@"

resp = requests.get("https://sonar.acme.internal/api/issues/search", auth=(SONAR_TOKEN, ""))
