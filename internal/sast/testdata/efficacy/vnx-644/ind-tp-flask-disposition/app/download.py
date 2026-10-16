from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/dl")
def dl():
    resp = make_response(load_report())
~>    resp.headers["Content-Disposition"] = "attachment; filename=" + request.args["file"]
    return resp
