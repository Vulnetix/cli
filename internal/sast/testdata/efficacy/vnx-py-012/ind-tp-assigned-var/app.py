from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/render")
def render():
    tpl = request.args.get("t", "")
~>    return render_template_string(tpl, user="guest")
