import os
from flask import Flask
app = Flask(__name__)
HOST = os.environ.get("BIND_HOST", "0.0.0.0")
if __name__ == "__main__":
    app.run(host=HOST, port=5000)
    app.run(host="127.0.0.1", port=5001)
