import requests


def fetch_orders(user: str, password: str) -> list:
    resp = requests.get("https://orders.acme-corp.com/api/orders", auth=(user, password), timeout=10)
    resp.raise_for_status()
    return resp.json()


def local_admin(token: str) -> dict:
    return requests.get("http://localhost:8080/admin/stats", headers={"Authorization": f"Bearer {token}"}).json()


def sidecar(token: str) -> dict:
    return requests.post("http://10.0.4.12:9000/v1/sign", headers={"X-Api-Key": token}).json()


def metrics_service(password: str) -> None:
    requests.post("http://metrics:9091/push", auth=("svc", password))


def notify(email: str) -> None:
    requests.post("http://hooks.acme-corp.com/notify", json={"text": "Password reset requested", "to": email})
