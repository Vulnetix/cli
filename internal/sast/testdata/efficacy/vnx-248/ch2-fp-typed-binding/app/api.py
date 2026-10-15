from flask import Flask, request

app = Flask(__name__)


@app.route("/n")
def n():
    page = request.args.get("page", 1, type=int)
    name = str(request.args.get("name"))
    count = len(request.form.getlist("ids"))
    return {"page": page, "name": name, "count": count}
