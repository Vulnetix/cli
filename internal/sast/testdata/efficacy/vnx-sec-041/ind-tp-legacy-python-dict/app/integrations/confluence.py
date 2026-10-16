import requests

CONFIG = {
    "base_url": "https://acme.atlassian.net/wiki",
~>    "confluence_api_token": "@@sample:[A-Za-z0-9]{24}@@",
}


def page(pid):
    return requests.get(f"{CONFIG['base_url']}/rest/api/content/{pid}")
