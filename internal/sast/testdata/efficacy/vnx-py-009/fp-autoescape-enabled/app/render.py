import aws_cdk as cdk
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
html_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
options = {"autoescape": True}
custom = Environment(**options)
stack_env = cdk.Environment(account="123456789012", region="eu-west-1")


def page(name):
    return env.get_template("page.html").render(name=name)
