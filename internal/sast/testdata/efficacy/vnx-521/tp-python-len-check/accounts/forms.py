from django import forms


class SignupForm(forms.Form):
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)

    def clean_password(self):
        password = self.cleaned_data["password"]
~>        if len(password) < 6:
            raise forms.ValidationError("Password too short")
        return password


def change_password(user, new_password):
~>    if len( new_password ) <= 4:
        return False
    user.set_password(new_password)
    return True


def acceptable(pwd):
~>    return len(pwd) >= 5
