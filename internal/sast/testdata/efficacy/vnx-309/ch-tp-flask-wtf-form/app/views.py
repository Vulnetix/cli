from flask import redirect, render_template
from flask_login import login_user
from .forms import LoginForm
from .models import User


def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
~>        if user and user.password == form.password.data:
            login_user(user)
            return redirect("/")
    return render_template("login.html", form=form)
