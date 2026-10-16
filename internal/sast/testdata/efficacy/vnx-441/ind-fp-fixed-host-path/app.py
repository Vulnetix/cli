from flask import Flask, jsonify, request
import requests

app = Flask(__name__)
GITHUB_API = "https://api.github.com"


@app.route("/repo-info")
def repo_info():
    owner = request.args.get("owner")
    repo = request.args.get("repo")
    r = requests.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=5)
    return jsonify(r.json()), r.status_code
