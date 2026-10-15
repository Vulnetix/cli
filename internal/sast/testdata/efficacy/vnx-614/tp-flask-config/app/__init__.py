from flask import Flask

app = Flask(__name__)
~>app.config["SESSION_COOKIE_SECURE"] = False
~>app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_HTTPONLY=True)
~>app.config['REMEMBER_COOKIE_SECURE'] = False
