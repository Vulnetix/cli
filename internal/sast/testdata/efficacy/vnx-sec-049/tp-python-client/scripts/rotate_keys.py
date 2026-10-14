import requests

~>ADMIN_KEY = "sk-ant-admin01-@@sample:[A-Za-z0-9]{93}@@AA"


def list_keys():
    resp = requests.get(
        "https://api.anthropic.com/v1/organizations/api_keys",
        headers={"x-api-key": ADMIN_KEY, "anthropic-version": "2023-06-01"},
    )
    return resp.json()
