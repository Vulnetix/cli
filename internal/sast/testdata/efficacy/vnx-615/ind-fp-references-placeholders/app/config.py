"""Application configuration.

Set the following in the environment:

    password = <your password>
    api_key = ${API_KEY}
"""
import os

from django.conf import settings

# password = os.environ["DB_PASSWORD"]
# api_key = settings.API_KEY
# secret = get_secret("payments/stripe")
# password=changeme
# access_token = xxxxxxxx
# passwd: ********
# docs: https://wiki.internal/ops/rotate?api_key=docs-example-1

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = settings.API_KEY
