from django import forms
from django.conf import settings


class ProfileForm(forms.Form):
    nickname = forms.CharField(min_length=3)
    pin_hint = forms.CharField(required=False)

    def clean_nickname(self):
        nickname = self.cleaned_data["nickname"]
        if len(nickname) < 3:
            raise forms.ValidationError("Nicknames need 3 or more characters")
        return nickname

    def clean_password(self):
        password = self.cleaned_data["password"]
        # Old policy was len(password) < 6, raised to 12 in 2024.
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            raise forms.ValidationError("Password must be at least 6 words long or 12 characters")
        return password


AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
