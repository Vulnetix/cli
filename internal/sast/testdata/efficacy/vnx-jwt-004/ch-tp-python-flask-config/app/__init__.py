from flask import Flask
from flask_jwt_extended import JWTManager

app = Flask(__name__)
~>app.config["JWT_ALGORITHM"] = "none"
~>app.config["JWT_DECODE_ALGORITHMS"] = ["HS256", "none"]
jwt = JWTManager(app)
