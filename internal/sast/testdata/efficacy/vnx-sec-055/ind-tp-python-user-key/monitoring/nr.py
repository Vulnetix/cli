import requests

~>NEW_RELIC_API_KEY = "@@sample:NRAK-[A-Z0-9]{27}@@"

def query(nrql):
    return requests.post("https://api.newrelic.com/graphql", headers={"API-Key": NEW_RELIC_API_KEY})
