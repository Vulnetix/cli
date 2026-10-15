import requests

session = requests.Session()
~>session.headers.update({"Authorization": "Bearer @@sample:[A-Za-z0-9]{32}@@"})
