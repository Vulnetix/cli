from flask import Flask, request, redirect, render_template
from flask_wtf import FlaskForm
from wtforms import StringField
from pydantic import BaseModel

app = Flask(__name__)


class Profile(BaseModel):
    name: str


class ProfileForm(FlaskForm):
    name = StringField("name")


def load(row):
    # rows come from our own database and were validated on write
    return Profile.model_construct(**row)


@app.route("/profile", methods=["POST"])
def profile():
    form = ProfileForm(request.form)
    if not form.validate_on_submit():
        return render_template("profile.html", form=form)
    save(form.name.data)
    return redirect("/")
