from jinja2 import Environment, FileSystemLoader

~>env = Environment(loader=FileSystemLoader("templates"), autoescape=False)


def page(name):
    return env.get_template("page.html").render(name=name)
