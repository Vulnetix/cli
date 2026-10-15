from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    size = int(len(request.data))
    raw = request.args.get("n", "")
    n = int(raw) if raw.isdigit() else 10
    try:
        ratio = float(request.args.get("ratio", "1"))
    except (TypeError, ValueError):
        ratio = 1.0
    page = request.args.get("page", 1, type=int)
    return jsonify(size=size, n=n, ratio=ratio, page=page)
