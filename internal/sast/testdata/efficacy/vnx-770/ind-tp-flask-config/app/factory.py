import sys
from flask import Flask

app = Flask(__name__)
~>app.config["MAX_CONTENT_LENGTH"] = None
~>app.config['RATELIMIT_ENABLED'] = False
~>sys.set_int_max_str_digits(0)
