from jinja2 import Environment


def test_raw_rendering():
    env = Environment(autoescape=False)
    assert env.from_string("{{ x }}").render(x="<b>") == "<b>"
