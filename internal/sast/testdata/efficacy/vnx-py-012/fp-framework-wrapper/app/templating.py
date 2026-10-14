from flask import current_app
from jinja2 import Environment


def render_template_string(source, **context):
    template = current_app.jinja_env.from_string(source)
    return template.render(context)


def render_named(env: Environment, name, data):
    src = env.loader.get_source(env, name)[0]
    return env.from_string(src).render(data)
