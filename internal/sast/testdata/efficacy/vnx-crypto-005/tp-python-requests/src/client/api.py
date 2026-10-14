import httpx
import requests


def fetch(url):
~>    return requests.get(url, verify=False)


def post(url, body):
~>    return requests.post(url, json=body, timeout=5, verify = False)


def make_session():
    s = requests.Session()
~>    s.verify = False
    return s


def multi_line(url):
    resp = requests.request(
        "GET",
        url,
~>        verify=False,
    )
    return resp


def with_httpx(url):
~>    with httpx.Client(base_url=url, verify=False) as client:
        return client.get("/health")
