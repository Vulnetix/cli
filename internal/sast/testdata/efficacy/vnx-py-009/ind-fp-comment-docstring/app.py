from jinja2 import Environment, select_autoescape


def make_env():
    """Never build this with autoescape=False; Environment(autoescape=False) is unsafe."""
    # old code used Environment(autoescape=False) here
    return Environment(autoescape=select_autoescape())
