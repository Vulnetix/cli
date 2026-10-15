import os

import httpx
import requests
from requests.auth import HTTPDigestAuth
from requests_ntlm import HttpNtlmAuth
import urllib.request


def fetch_report(url):
    user, pw = os.environ["RPT_USER"], os.environ["RPT_PASS"]
~>    return requests.get(url, auth=HTTPDigestAuth(user, pw))


def fetch_share(url):
~>    session_auth = HttpNtlmAuth("CORP\\svc", os.environ["SVC_PW"])
    return requests.get(url, auth=session_auth)


def fetch_httpx(url, user, pw):
~>    with httpx.Client(auth=httpx.DigestAuth(user, pw)) as c:
        return c.get(url)


def opener(mgr):
~>    handler = urllib.request.HTTPDigestAuthHandler(mgr)
    return urllib.request.build_opener(handler)
