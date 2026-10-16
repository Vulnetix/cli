from django import forms
from django.core.exceptions import ValidationError


class SignupForm(forms.Form):
    username = forms.CharField(max_length=40)
    email = forms.EmailField()

    def clean_username(self):
        username = self.cleaned_data["username"]
~>        if username == "admin" or username == "root":
            raise ValidationError("This name is reserved.")
        return username
