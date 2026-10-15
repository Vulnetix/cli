import requests

~>headers = {"Authorization": "token @@sample:ghu_[A-Za-z0-9]{36}@@"}
requests.get("https://api.github.com/user", headers=headers)
