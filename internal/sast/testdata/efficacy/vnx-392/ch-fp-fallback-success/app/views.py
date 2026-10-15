from flask import Flask, jsonify, abort

app = Flask(__name__)


@app.get("/feed")
def feed():
    try:
        items = load_feed()
    except TimeoutError:
        return jsonify(items=[], cached=True)
    except PermissionError:
        abort(403)
    return jsonify(items=items)


@app.get("/form")
def form():
    try:
        validate()
    except ValueError as e:
        return render_template("form.html", error=str(e))
    return jsonify(ok=True)
