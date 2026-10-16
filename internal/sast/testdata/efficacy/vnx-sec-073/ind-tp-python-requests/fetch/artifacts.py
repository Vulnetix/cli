import requests


def download_build():
    # internal artifact repository
    resp = requests.get(
~>        "https://ci-bot:Zq8vT3mK9xL2@nexus.acme-corp.io/repository/raw/build.tgz",
        timeout=30,
    )
    resp.raise_for_status()
    return resp.content
