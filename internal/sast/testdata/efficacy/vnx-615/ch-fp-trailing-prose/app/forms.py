from django import forms


class SignupForm(forms.Form):
    password = forms.CharField(min_length=12)  # password: at least 12 characters
    api_key = forms.CharField(required=False)  # api_key: optional, from settings
    url = "http://example.com/#token=abc"
