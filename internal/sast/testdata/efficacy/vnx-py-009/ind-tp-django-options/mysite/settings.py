TEMPLATES = [
    {
        "BACKEND": "django.template.backends.jinja2.Jinja2",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
~>            "autoescape": False,
            "environment": "mysite.jinja2.environment",
        },
    },
]
