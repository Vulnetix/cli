MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

X_FRAME_OPTIONS = "DENY"
# X_FRAME_OPTIONS = 'ALLOWALL'
CSP_FRAME_ANCESTORS = ("'self'",)
