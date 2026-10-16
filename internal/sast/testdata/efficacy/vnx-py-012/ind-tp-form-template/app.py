from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/preview", methods=["POST"])
def preview():
~>    return render_template_string(request.form["template"])
