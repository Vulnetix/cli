import requests

~>SERVICE_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZyIsInJvbGUiOiJzZXJ2aWNlIiwiaWF0IjoxNzYwMDAwMDAwfQ.@@sample:[A-Za-z0-9_\-]{43}@@"


def invoices(customer_id):
    return requests.get(
        f"https://billing.acme.invalid/v1/customers/{customer_id}/invoices",
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
        timeout=10,
    ).json()
