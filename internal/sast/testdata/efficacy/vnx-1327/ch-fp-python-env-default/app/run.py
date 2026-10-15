import os
from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=int(os.environ.get("PORT", "5000")))
