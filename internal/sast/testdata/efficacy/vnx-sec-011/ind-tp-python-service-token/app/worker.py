import requests

BASE = "https://reports.shop.example/api"
~>SERVICE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZy13b3JrZXIiLCJyb2xlIjoic2VydmljZSIsImlzcyI6Imh0dHBzOi8vYXV0aC5zaG9wLmV4YW1wbGUifQ.mBgaOqm_LNrFj67KldMq0hO_Li3NPHq5jwEEki1oX7c"


def fetch_report(report_id):
    resp = requests.get(
        f"{BASE}/reports/{report_id}",
        headers={"Authorization": "Bearer " + SERVICE_TOKEN},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()
