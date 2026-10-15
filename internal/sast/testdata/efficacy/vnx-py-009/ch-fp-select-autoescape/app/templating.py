from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(
    loader=PackageLoader("app"),
    autoescape=select_autoescape(["html", "htm", "xml"]),
)

strict_env = Environment(loader=PackageLoader("app"), autoescape=True)


def render(name, **ctx):
    return env.get_template(name).render(**ctx)
