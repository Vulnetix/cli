from django import forms


class ChangePasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput)

    def clean_new_password(self):
        new_password = self.cleaned_data["new_password"]
~>        if len(new_password) < 6:
            raise forms.ValidationError("Password must be at least 6 characters")
        return new_password
