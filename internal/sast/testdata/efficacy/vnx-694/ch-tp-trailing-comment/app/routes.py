from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


~>@app.route("/health")  # kept for the old load balancer
def health_legacy():
    return "ok"
