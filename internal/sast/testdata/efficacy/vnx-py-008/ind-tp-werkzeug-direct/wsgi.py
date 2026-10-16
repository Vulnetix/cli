from flask import Flask
from werkzeug.serving import run_simple
from werkzeug.debug import DebuggedApplication

application = Flask(__name__)

~>wsgi_app = DebuggedApplication(application, evalex=True)

if __name__ == "__main__":
~>    run_simple("0.0.0.0", 5000, application, use_debugger=True)
