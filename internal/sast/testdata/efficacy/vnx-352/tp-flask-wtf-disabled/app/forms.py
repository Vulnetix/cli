from flask_wtf import FlaskForm
from wtforms import StringField


class ProfileForm(FlaskForm):
    name = StringField("name")

    class Meta:
~>        csrf = False


def make_form():
~>    return ProfileForm(meta={"csrf": False})
