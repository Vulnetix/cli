from flask import Flask, request

app = Flask(__name__)
LINE_WIDTH = 72


@app.route("/banner")
def banner():
    title = request.args.get("title", "")
    header = "=" * LINE_WIDTH + "\n" + title
    return header
