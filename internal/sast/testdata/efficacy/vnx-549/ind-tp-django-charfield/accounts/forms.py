from django import forms


class RegistrationForm(forms.Form):
    email = forms.EmailField()
~>    password = forms.CharField(label="Password", max_length=128, min_length=12)
    password_hint = forms.CharField(required=False)
