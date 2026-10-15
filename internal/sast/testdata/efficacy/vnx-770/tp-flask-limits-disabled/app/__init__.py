import sys

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
~>app.config["MAX_CONTENT_LENGTH"] = None
~>app.config['RATELIMIT_ENABLED'] = False
~>limiter = Limiter(get_remote_address, app=app, enabled=False)
~>sys.set_int_max_str_digits(0)


class ProductionConfig:
~>    RATELIMIT_ENABLED = False
~>    MAX_CONTENT_LENGTH = None
