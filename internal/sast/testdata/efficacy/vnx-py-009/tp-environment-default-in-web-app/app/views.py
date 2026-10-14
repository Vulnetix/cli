from flask import Flask
from jinja2 import Environment, PackageLoader

app = Flask(__name__)
~>jinja = Environment(loader=PackageLoader("app", "templates"))


@app.route("/profile")
def profile():
    return jinja.get_template("profile.html").render(user=current_user())
