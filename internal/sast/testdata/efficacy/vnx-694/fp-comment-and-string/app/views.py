from flask import Flask

app = Flask(__name__)

# @app.route("/health")
HELP = '@app.route("/health")'


@app.route("/health")
def health():
    return "ok"
