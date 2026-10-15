import requests


def login(username, password):
    requests.post("https://api.partner-billing.com/v2/login", data={"username": username, "password": password})
    requests.post("http://localhost:8080/login", data={"password": password})
    requests.post("http://10.0.3.17/login", data={"password": password})
    requests.post("http://auth-service:9000/login", json={"password": password})
    requests.get("http://status.partner-billing.com/health", timeout=3)
