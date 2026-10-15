from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/download")
def download():
    resp = make_response(load(request.args["file"]))
~>    resp.headers["Content-Disposition"] = "attachment; filename=" + request.args["file"]
~>    resp.headers.add("X-Request-Label", request.headers.get("X-Label"))
    return resp


@app.route("/echo")
def echo():
    lang = request.args.get("lang", "en")
    resp = make_response("ok")
~>    resp.headers['Content-Language'] = lang
~>    return Response("ok", headers={"X-Trace": request.headers["X-Trace"]})
