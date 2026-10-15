import jinja2
from flask import Flask

app = Flask(__name__)
~>app.jinja_env.autoescape=False


def render_banner(src, **ctx):
~>    tpl = jinja2.Template(src, autoescape=False)
    return tpl.render(**ctx)
