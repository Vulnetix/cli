from datetime import timedelta

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]
~>PASSWORD_EXPIRY_DAYS = 365
~>PASSWORD_MAX_AGE = timedelta(days=400)
SESSION_COOKIE_AGE = 1209600
