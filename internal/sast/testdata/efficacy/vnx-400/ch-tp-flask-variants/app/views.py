import time

from flask import Flask, request

app = Flask(__name__)


@app.get("/pad")
def pad():
    width = request.args.get("width", type=int)
~>    return "0" * width


@app.get("/slow")
def slow():
~>    time.sleep(float(request.args["delay"]))
    return "ok"


@app.post("/buf")
def buf():
    size = request.json.get("size")
~>    data = bytearray(size)
    return {"len": len(data)}


@app.get("/steps")
def steps():
    n = int(request.form["n"])
    out = []
~>    for i in range(1, n + 1):
        out.append(i * i)
    return {"out": out}
