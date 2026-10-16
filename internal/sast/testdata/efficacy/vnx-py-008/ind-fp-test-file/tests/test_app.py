from flask import Flask

app = Flask(__name__)
app.debug = True


def test_it():
    app.run(debug=True)
