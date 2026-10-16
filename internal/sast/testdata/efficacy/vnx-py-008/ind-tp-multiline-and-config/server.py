from flask import Flask

api = Flask(__name__)
~>api.debug = True
~>api.config["DEBUG"] = True
~>api.config.update(DEBUG=True, TESTING=False)


def main():
~>    api.run(
        host="0.0.0.0",
        port=8080,
        debug=True,
    )
