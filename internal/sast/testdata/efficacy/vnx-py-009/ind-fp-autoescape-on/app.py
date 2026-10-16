from flask import Flask
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = Flask(__name__)
env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
env2 = Environment(
    loader=FileSystemLoader("mail"),
    autoescape=select_autoescape(["html", "xml"]),
)
app.jinja_env.autoescape = True
