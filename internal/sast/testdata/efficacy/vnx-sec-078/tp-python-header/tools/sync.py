import requests

~>HEADERS = {"Authorization": "Bearer dp.pt.@@sample:[A-Za-z0-9]{43}@@"}
resp = requests.get("https://api.doppler.com/v3/projects", headers=HEADERS)
