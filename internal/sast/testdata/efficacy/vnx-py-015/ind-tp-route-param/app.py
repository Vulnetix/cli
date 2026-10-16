import re
from flask import Flask

app = Flask(__name__)


@app.route("/grep/<pat>")
def grep(pat):
~>    return str(re.match(pat, "sample text") is not None)
