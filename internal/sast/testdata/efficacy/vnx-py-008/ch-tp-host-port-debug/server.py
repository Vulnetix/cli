from flask import Flask, jsonify

api = Flask(__name__)


@api.route("/health")
def health():
    return jsonify(ok=True)


if __name__ == "__main__":
~>    api.run(host="0.0.0.0", port=5000, debug = True)
