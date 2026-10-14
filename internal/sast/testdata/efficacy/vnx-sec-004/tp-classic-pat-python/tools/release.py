import requests

~>GH_TOKEN = "@@sample:ghp_[A-Za-z0-9]{36}@@"

def tag(repo):
    return requests.post(f"https://api.github.com/repos/{repo}/git/refs",
                         headers={"Authorization": f"token {GH_TOKEN}"})
