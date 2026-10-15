AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
]


def clean(password):
    if len(password) < 12:
        raise ValueError("too short")
    return len(password) >= 8
