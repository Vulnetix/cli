from django import forms


class SignupForm(forms.Form):
    def clean(self):
        data = super().clean()
        if data.get("password1") != data.get("password2"):
            raise forms.ValidationError("Passwords do not match")
        if data["password"] != data["confirm_password"]:
            raise forms.ValidationError("Passwords do not match")
        if new_password == user.password:
            raise forms.ValidationError("Choose a different password")
        return data
