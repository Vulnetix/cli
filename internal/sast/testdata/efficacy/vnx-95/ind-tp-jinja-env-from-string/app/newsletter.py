from jinja2 import Environment, select_autoescape
from flask import Blueprint, request

bp = Blueprint("newsletter", __name__)
jinja_env = Environment(autoescape=select_autoescape(["html"]))


@bp.route("/newsletter/preview", methods=["POST"])
def preview():
    template_source = request.form.get("template", "")
~>    template = jinja_env.from_string(template_source)
    return template.render(subscriber={"name": "Preview User"})
