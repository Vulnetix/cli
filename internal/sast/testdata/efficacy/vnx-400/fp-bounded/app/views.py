from flask import Flask, abort, jsonify, request

app = Flask(__name__)
MAX_COUNT = 100


@app.route("/codes")
def codes():
    n = min(request.args.get("count", 10, type=int), MAX_COUNT)
    return jsonify([make_code() for _ in range(n)])


@app.route("/pages")
def pages():
    pages = int(request.args["pages"])
    if pages > 50 or pages < 1:
        abort(400)
    return jsonify([render_page(i) for i in range(pages)])


@app.route("/batch")
def batch():
    size = request.args.get("size", type=int)
    size = max(1, min(size, 500))
    for offset in range(size):
        process(offset)
    return "", 204


@app.route("/names")
def names():
    name = request.args.get("name", "")
    return jsonify(["*" * len(name)])
