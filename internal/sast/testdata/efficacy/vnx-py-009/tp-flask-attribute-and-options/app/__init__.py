from flask import Flask


class LegacyFlask(Flask):
~>    jinja_options = {"autoescape": False, "trim_blocks": True}


def create_app():
    app = LegacyFlask(__name__)
~>    app.jinja_env.autoescape = False
    return app
