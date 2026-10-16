import requests

headers = {
~>    "Authorization": "token @@sample:gho_[A-Za-z0-9]{36}@@",
    "Accept": "application/vnd.github+json",
}
requests.get("https://api.github.com/user", headers=headers)
