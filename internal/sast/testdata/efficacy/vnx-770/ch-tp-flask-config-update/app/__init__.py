from flask import Flask

app = Flask(__name__)
~>app.config.update(SECRET_KEY=load_key(), MAX_CONTENT_LENGTH=None)
