import os
import site
from flask import request


def configure():
~>    os.environ["LD_LIBRARY_PATH"] = request.json.get("libdir")


def addsite():
    extra = request.form["site"]
~>    site.addsitedir(extra)
