import requests
import subprocess


def fetch_invoice(url, timeout=10, verify=True):
    return requests.get(url, timeout=timeout, verify=verify)


def legacy_fetch(url):
    # The caller opts out explicitly; this rule is about defaults, not calls.
    return requests.get(url, verify=False)


def set_session_cookie(response, value, secure=True, httponly=True):
    response.set_cookie(
        "session",
        value,
        secure=False,
        httponly=True,
    )


def run_tool(cmd, shell=False, debug=False):
    subprocess.run(cmd, shell=True)
    return subprocess.run(cmd, check=True)


def connect(host, ssl=False, use_tls=False, port=6379):
    return host


def configure(verify=None, insecure=False):
    return verify
