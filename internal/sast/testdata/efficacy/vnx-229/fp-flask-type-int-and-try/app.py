from flask import Flask, request, abort

app = Flask(__name__)


@app.route("/items")
def items():
    page = request.args.get("page", 1, type=int)
    try:
        size = int(request.args.get("size", 20))
        offset = int(request.args["offset"])
    except (TypeError, ValueError):
        abort(400)
    count = int(len(page_items))
    return render(page, size, offset, count)
