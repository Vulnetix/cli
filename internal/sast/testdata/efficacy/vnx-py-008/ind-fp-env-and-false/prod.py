import os
from flask import Flask

app = Flask(__name__)
app.config["DEBUG"] = False

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
    app.run(host="0.0.0.0", debug=False)
