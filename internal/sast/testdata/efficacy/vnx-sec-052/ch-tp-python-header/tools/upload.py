import requests

~>ART_KEY = "AKCp@@sample:[A-Za-z0-9]{69}@@"

def upload(path, url):
    with open(path, "rb") as fh:
        return requests.put(url, data=fh, headers={"X-JFrog-Art-Api": ART_KEY})
