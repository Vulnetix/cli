from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/codes")
def codes():
    n = request.args.get("count", type=int)
~>    return jsonify([make_code() for _ in range(n)])


@app.route("/pages")
def pages():
    items = []
~>    for i in range(int(request.args["pages"])):
        items.append(render_page(i))
    return jsonify(items)


@app.route("/batch", methods=["POST"])
def batch():
    size = int(request.json.get("size", 10))
~>    for offset in range(0, size):
        process(offset)
    return "", 204
