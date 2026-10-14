from flask import Flask


def test_debug_page():
    app = Flask(__name__)
    app.debug = True
    app.run(debug=True)
