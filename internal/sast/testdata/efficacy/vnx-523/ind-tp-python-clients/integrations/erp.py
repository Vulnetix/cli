import httpx
import requests

ERP_BASE = "https://erp.acme-corp.com"


def fetch_orders(user: str, password: str) -> list:
~>    resp = requests.get("http://orders.acme-corp.com/api/orders", auth=(user, password), timeout=10)
    resp.raise_for_status()
    return resp.json()


def push_invoice(invoice: dict, api_token: str) -> None:
~>    httpx.post(
        "http://billing.partner-ledger.net/v1/invoices",
        json=invoice,
        headers={"Authorization": f"Bearer {api_token}"},
    )


def login(session: requests.Session, username: str, password: str) -> None:
~>    session.post("http://portal.supplier-hub.com/login", data={"username": username, "password": password})
