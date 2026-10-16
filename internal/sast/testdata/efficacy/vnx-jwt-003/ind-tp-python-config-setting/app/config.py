from flask import Flask

app = Flask(__name__)
~>app.config["JWT_SECRET_KEY"] = "dev-only-but-committed-secret-value"
app.config["JWT_ALGORITHM"] = "HS256"
