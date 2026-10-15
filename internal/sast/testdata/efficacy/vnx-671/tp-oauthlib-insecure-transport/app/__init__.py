import os
from flask import Flask

~>os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
~>os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'

app = Flask(__name__)
