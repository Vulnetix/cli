import requests

GRAFANA = "https://grafana.acme.internal"
~>API_KEY = "eyJrIjoi@@sample:[A-Za-z0-9]{76}@@"

def list_dashboards():
    return requests.get(GRAFANA + "/api/search", headers={"Authorization": "Bearer " + API_KEY}).json()
