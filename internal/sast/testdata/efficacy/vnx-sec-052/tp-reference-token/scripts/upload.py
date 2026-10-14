import requests

~>TOKEN = "cmVmdGtuOjAxOjE3@@sample:[A-Za-z0-9]{48}@@"

def upload(path):
    with open(path, "rb") as fh:
        requests.put(
            "https://acme.jfrog.io/artifactory/generic-local/" + path,
            headers={"Authorization": f"Bearer {TOKEN}"},
            data=fh,
        )
