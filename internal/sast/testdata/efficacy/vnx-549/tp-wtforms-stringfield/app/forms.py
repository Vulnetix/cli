from wtforms import Form, StringField
from wtforms.validators import DataRequired


class SignupForm(Form):
    email = StringField("Email", validators=[DataRequired()])
~>    password = StringField("Password", validators=[DataRequired()])
