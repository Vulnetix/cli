import requests as rq


def version(host):
    page = rq.get(f"http://{host}/version", timeout=2)
~>    body = page.text
    return body.strip()
