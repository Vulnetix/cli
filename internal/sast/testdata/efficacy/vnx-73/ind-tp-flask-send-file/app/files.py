from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download")
def download():
~>    return send_file(request.args.get("path"), as_attachment=True)
