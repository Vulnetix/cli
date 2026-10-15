import requests


def download(url, dest):
    with requests.get(url, stream=True, timeout=30) as resp:
        with open(dest, "wb") as fh:
~>            fh.write(resp.content)


def download_checked(url, dest):
    with requests.get(url, stream=True, timeout=30) as resp:
        resp.raise_for_status()
        with open(dest, "wb") as fh:
            fh.write(resp.content)
