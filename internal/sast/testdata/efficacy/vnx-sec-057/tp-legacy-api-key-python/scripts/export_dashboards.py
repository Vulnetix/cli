import requests

GRAFANA = "https://grafana.acme.internal"
~>API_KEY = "eyJrIjoi@@sample:[A-Za-z0-9]{76}@@"

resp = requests.get(f"{GRAFANA}/api/search", headers={"Authorization": f"Bearer {API_KEY}"})
