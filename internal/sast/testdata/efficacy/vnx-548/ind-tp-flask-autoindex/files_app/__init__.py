import os

from flask import Flask
from flask_autoindex import AutoIndex

app = Flask(__name__)
FILES_DIR = os.environ.get("FILES_DIR", "/srv/share")
~>AutoIndex(app, browse_root=FILES_DIR)
