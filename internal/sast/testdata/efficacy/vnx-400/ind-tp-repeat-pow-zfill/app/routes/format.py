from flask import Flask, request

app = Flask(__name__)


@app.post("/banner")
def banner():
    width = int(request.form["width"])
~>    line = "=" * width
    return line


@app.get("/power")
def power():
    exp = int(request.form["exp"])
~>    return str(10 ** exp)


@app.get("/invoice-number")
def invoice_number():
    digits = int(request.args.get("digits", "8"))
    raw = str(request.args.get("seq", "1"))
~>    return raw.zfill(digits)
