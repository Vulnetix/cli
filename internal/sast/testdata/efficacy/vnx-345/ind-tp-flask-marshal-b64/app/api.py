import base64
import marshal
import types

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/jobs", methods=["POST"])
def submit_job():
    payload = request.get_data()
    raw = base64.b64decode(payload)
~>    code = marshal.loads(raw)
    fn = types.FunctionType(code, globals(), "job")
    return jsonify(result=fn())
