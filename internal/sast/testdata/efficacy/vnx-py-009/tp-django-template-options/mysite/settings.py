DEBUG = False

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
~>            'autoescape': False,
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]
