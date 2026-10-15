import requests


def fetch_orders(user, password):
    return requests.get("https://orders.acme-corp.com/api/orders", auth=(user, password))


def local(user, password):
    return requests.post("http://localhost:8080/login", data={"password": password})


def internal(token):
    return requests.get("http://127.0.0.1:9000/x", headers={"Authorization": token})


def example(password):
    return requests.post("http://example.com/login", data={"password": password})


REDIS = "http://user:pass@cache:6379"
