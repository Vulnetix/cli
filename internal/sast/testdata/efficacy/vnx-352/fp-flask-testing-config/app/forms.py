from flask_wtf import FlaskForm


class SearchForm(FlaskForm):
    class Meta:
        csrf = True


def build(app):
    if app.testing:
        app.config["WTF_CSRF_ENABLED"] = False
    return app
