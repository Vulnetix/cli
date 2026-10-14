from werkzeug.debug import DebuggedApplication
from werkzeug.serving import run_simple

from server.app import app

~>wsgi_app = DebuggedApplication(app, evalex=True)

if __name__ == "__main__":
~>    run_simple("0.0.0.0", 8080, wsgi_app, use_reloader=True, use_debugger=True)
