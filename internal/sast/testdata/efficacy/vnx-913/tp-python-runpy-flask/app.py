import runpy
from flask import Flask, request

app = Flask(__name__)


@app.route("/job")
def job():
    script = request.args.get("script")
~>  result = runpy.run_path(script)
    return str(result.get("status"))


@app.route("/mod")
def mod():
~>  runpy.run_module(request.args["module"], run_name="__main__")
    return "done"
