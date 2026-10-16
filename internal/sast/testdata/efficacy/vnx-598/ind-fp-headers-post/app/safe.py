import requests


def a(url, api_key):
    return requests.get(url, headers={"X-Api-Key": api_key})


def b(base, password):
    return requests.post(base + "/token", data="grant_type=password&password=" + password)


def c(base):
    return requests.get(base + "/items?pageToken=abc&next_token=zzz")


EXAMPLE = "https://api.example.com/v1/items?api_key=YOUR_API_KEY"
# url = f"{base}/login?password={password}"
