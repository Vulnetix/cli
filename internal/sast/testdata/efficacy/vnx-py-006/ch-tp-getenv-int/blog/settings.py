import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

~>DEBUG=bool(int(os.getenv("DJANGO_DEBUG", "1")))

MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
DATABASES = {"default": {"ENGINE": "@@sample:d[j]an[g]o[.][d]b[.][b]ac[k]en[d]s[.][s]ql[i]te[3]@@"}}
