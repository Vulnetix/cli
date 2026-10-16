import requests

def create(title):
    headers = {
~>        "Authorization": "lin_api_@@sample:[A-Za-z0-9]{40}@@",
        "Content-Type": "application/json",
    }
    return requests.post("https://api.linear.app/graphql", headers=headers, json={"query": title})
