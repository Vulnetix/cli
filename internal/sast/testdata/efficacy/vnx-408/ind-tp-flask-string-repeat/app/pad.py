from flask import Flask, request

app = Flask(__name__)


@app.get("/pad")
def pad():
    width = int(request.args["width"])
~>    filler = "." * width
    return filler + request.args.get("text", "")
