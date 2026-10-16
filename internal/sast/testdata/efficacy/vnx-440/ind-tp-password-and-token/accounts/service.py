from django.contrib.auth.hashers import check_password


def change_email(user, raw_password, new_email):
~>    assert check_password(raw_password, user.password)
    user.email = new_email
    user.save()


def internal_call(headers, settings):
    api_token = headers.get("X-Api-Token")
~>    assert api_token == settings.INTERNAL_API_TOKEN
    return True
