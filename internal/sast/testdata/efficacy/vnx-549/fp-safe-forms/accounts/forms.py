from django import forms
from wtforms import PasswordField


class LoginForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )
    new_password = PasswordField("New password")
    password_hint = forms.CharField(max_length=60)
