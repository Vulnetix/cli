import os

from flask import Flask

basedir = os.path.abspath(os.path.dirname(__file__))
~>app = Flask(__name__, static_folder=basedir, static_url_path="/")
~>admin = Flask("admin", static_folder=os.path.abspath(os.path.dirname(__file__)))
