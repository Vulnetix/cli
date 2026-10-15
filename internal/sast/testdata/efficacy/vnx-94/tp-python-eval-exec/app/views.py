from flask import Flask, request

app = Flask(__name__)


@app.route("/eval")
def evaluate():
~>    return str(eval(request.args.get("q")))


@app.route("/run", methods=["POST"])
def run():
    code = request.form["code"]
~>    exec(code, {"__builtins__": {}})
~>    compiled = compile(request.json["src"], "<user>", "exec")
    return "ok"


def django_view(request):
    expr = request.GET.get("expr", "")
    line = f"result = {expr}"
~>    exec(line)
    return None
