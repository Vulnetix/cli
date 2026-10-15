from django import forms
from django.contrib.auth.models import User


class SignupForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

    def clean_username(self):
        if User.objects.filter(username=self.cleaned_data["username"]).exists():
            raise forms.ValidationError("That username is already taken.")
        return self.cleaned_data["username"]

    def clean_password(self):
        if len(self.cleaned_data["password"]) < 12:
            raise forms.ValidationError("Password is too short.")
        return self.cleaned_data["password"]
