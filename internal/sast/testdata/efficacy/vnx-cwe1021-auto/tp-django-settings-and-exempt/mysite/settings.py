from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Partners embed the dashboard.
~>X_FRAME_OPTIONS = 'ALLOWALL'

~>CSP_FRAME_ANCESTORS = ("*",)
