import requests

resp = requests.get(
    "https://api.doppler.com/v3/configs/config/secrets/download",
    params={"format": "json"},
~>    auth=("@@sample:dp\.pt\.[A-Za-z0-9]{43}@@", ""),
)
