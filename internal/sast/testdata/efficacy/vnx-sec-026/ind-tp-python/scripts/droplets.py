import requests

headers = {
~>    "Authorization": "Bearer dop_v1_@@sample:[0-9a-f]{64}@@",
    "Content-Type": "application/json",
}
r = requests.get("https://api.digitalocean.com/v2/droplets", headers=headers)
