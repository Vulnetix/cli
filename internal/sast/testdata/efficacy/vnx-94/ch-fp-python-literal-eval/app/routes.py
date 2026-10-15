import ast
import json

from flask import Flask, request

app = Flask(__name__)


@app.post("/settings")
def settings():
    # eval(request.form["x"]) would be code injection; literal_eval only reads literals.
    prefs = ast.literal_eval(request.form["prefs"])
    extra = json.loads(request.data)
    model.eval()
    doc = "use eval(request.args['q']) at your peril"
    return {"prefs": prefs, "extra": extra, "doc": doc}
