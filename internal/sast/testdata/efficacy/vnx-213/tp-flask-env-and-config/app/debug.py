import os

from django.http import JsonResponse
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/status")
def status():
~>    return jsonify(status="ok", environment=dict(os.environ))


@app.route("/config")
def config():
~>    return jsonify({k: str(v) for k, v in app.config.items()})


def env_view(request):
~>    return JsonResponse(os.environ.copy())
