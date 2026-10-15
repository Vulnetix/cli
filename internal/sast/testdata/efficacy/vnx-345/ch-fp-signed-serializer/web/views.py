import json

from flask import Flask, request
from itsdangerous import URLSafeSerializer

app = Flask(__name__)
signer = URLSafeSerializer("server-side-secret-from-env", serializer=json)


@app.route("/prefs")
def prefs():
    data = signer.loads(request.cookies.get("prefs", ""))
    return data.get("theme", "light")


def cache_dump(obj):
    import pickle
    return pickle.dumps(obj)
