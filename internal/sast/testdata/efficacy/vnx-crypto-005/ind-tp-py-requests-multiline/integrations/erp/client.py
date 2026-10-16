import requests


class ErpClient:
    def __init__(self, base_url: str, api_user: str):
        self.base_url = base_url
        self.api_user = api_user

    def push_order(self, order: dict) -> dict:
        resp = requests.post(
            f"{self.base_url}/orders",
            json=order,
~>            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
