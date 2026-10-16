from flask import Flask, request, send_from_directory

app = Flask(__name__)
UPLOADS = "/srv/uploads"


@app.route("/download")
def download():
    return send_from_directory(UPLOADS, request.args.get("path"), as_attachment=True)
