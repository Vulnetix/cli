import urllib.request
from flask import request

def dl():
    u = request.json["src"]
~>    data = urllib.request.urlopen(u, timeout=5)
    store(data)
