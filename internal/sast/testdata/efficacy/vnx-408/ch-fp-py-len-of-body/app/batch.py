from flask import Flask, request

app = Flask(__name__)


@app.route("/batch", methods=["POST"])
def batch():
    items = request.get_json()["items"]
    results = []
    for i in range(len(items)):
        results.append(process(items[i]))
    return {"results": results}
