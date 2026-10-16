import os
from flask import Flask

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ["JWT_SECRET_KEY"]
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
