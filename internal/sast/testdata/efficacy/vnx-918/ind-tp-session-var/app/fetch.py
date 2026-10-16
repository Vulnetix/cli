import requests
from flask import request

session = requests.Session()

def pull():
    target = request.args.get("url")
~>    resp = session.get(target, timeout=5)
    log.info(resp.status_code)
