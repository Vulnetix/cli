from django import forms
from django.contrib.auth import get_user_model


class SignupForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = get_user_model()
        fields = ("username", "email")

    def clean_password1(self):
        new_password = self.cleaned_data["password1"]
~>        if len(new_password) < 6:
            raise forms.ValidationError("Use at least 6 characters.")
        return new_password
