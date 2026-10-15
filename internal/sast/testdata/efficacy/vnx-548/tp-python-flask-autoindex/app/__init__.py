from flask import Flask
from flask_autoindex import AutoIndex

app = Flask(__name__)
~>AutoIndex(app, browse_root="/srv/share", add_url_rules=True)
