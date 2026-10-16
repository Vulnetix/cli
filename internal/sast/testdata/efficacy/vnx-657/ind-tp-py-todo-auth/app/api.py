from flask import Flask

app = Flask(__name__)


@app.route("/export")
def export():
~>    # TODO: add authentication before release
    return dump_everything()
