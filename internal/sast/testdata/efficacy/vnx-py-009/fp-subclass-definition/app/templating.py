from jinja2 import Environment as BaseEnvironment


class Environment(BaseEnvironment):
    """Environment that knows about the application's blueprints."""

    def __init__(self, app, **options):
        if "loader" not in options:
            options["loader"] = app.create_global_jinja_loader()
        BaseEnvironment.__init__(self, **options)


def create_jinja_environment(app) -> Environment:
    options = dict(app.jinja_options)
    options.setdefault("autoescape", app.select_jinja_autoescape)
    return Environment(app, **options)


def render(app):
    return create_jinja_environment(app).get_template("index.html").render()
