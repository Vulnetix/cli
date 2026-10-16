from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
~>    password = StringField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Sign in")
