import requests

HEADERS = {
~>    "Authorization": "Bearer sntryu_@@sample:[a-f0-9]{64}@@",
}
requests.put("https://sentry.io/api/0/projects/acme/web/issues/", headers=HEADERS, json={"status": "resolved"})
