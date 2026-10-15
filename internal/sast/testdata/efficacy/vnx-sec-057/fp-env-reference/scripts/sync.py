import os

token = os.environ["GRAFANA_SA_TOKEN"]
headers = {"Authorization": f"Bearer {token}"}
