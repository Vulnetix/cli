import requests

~>HEADERS = {"Authorization": "lin_api_@@sample:[A-Za-z0-9]{40}@@"}
requests.post("https://api.linear.app/graphql", json={"query": "{ viewer { id } }"}, headers=HEADERS)
