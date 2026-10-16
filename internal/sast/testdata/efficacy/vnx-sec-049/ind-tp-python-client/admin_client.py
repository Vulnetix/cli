import requests

BASE = "https://api.anthropic.com/v1/organizations"
~>ADMIN_KEY = "@@sample:sk-ant-admin01-[A-Za-z0-9_-]{93}AA@@"

def list_users():
    return requests.get(BASE + "/users", headers={"x-api-key": ADMIN_KEY, "anthropic-version": "2023-06-01"})
