import requests

def query(gql):
    return requests.post(
        "https://api.newrelic.com/graphql",
~>        headers={"API-Key": "NRAK-@@sample:[A-Z0-9]{27}@@"},
        json={"query": gql},
    )
