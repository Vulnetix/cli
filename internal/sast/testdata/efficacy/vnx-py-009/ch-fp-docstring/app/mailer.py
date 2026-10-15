from flask import Flask
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)


def build_env(root):
    """Build the template environment.

    Never construct Environment(autoescape=False) here: the mail bodies
    include user names. app.jinja_env.autoescape = False is equally wrong.
    """
    return Environment(
        loader=FileSystemLoader(root),
        autoescape=select_autoescape(),
    )
