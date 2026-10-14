import requests

~>NEW_RELIC_API_KEY = "NRAK-@@sample:[A-Z0-9]{27}@@"

resp = requests.post(
    "https://api.newrelic.com/graphql",
    headers={"API-Key": NEW_RELIC_API_KEY},
    json={"query": "{ actor { user { name } } }"},
)
