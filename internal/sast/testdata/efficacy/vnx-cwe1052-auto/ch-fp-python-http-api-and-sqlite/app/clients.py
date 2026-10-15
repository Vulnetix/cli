import sqlite3

import requests
from sqlalchemy import create_engine

API = "https://api.github.com"

engine = create_engine("sqlite:///var/lib/app/app.db")
conn = sqlite3.connect("/var/lib/app/cache.db")


def repo(name):
    return requests.get(f"{API}/repos/{name}", timeout=10).json()


def status():
    return requests.get("https://status.acme-corp.net/api/v2/status.json", timeout=5)
