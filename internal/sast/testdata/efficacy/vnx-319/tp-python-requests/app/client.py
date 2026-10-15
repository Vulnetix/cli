import requests
import urllib.request

~>resp = requests.post("http://payments.partner-bank.com/v1/charge", json=payload)
~>BASE_URL = "http://api.weather-provider.net"
~>with urllib.request.urlopen(f"http://inventory.acme-corp.io/items/{sku}") as r:
    data = r.read()
