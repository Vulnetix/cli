from flask import Flask, request, jsonify

app = Flask(__name__)

LAST_LOOKUP = None
HANDLERS = {"csv": lambda d: d, "json": lambda d: d}


@app.route("/lookup")
def lookup():
    name = request.args.get("name", "")
    globals()["LAST_LOOKUP"] = name
    handler = HANDLERS.get(request.args.get("format", "json"))
    if handler is None:
        return jsonify(error="unknown format"), 400
    return jsonify(result=handler(name))


def configure(overrides):
    # globals()[key] = value would be dangerous with request data
    for key, value in overrides.items():
        globals()[key] = value
