# Never ship app.run(debug=True): the Werkzeug console is remote code execution.
from flask import Flask

app = Flask(__name__)
USAGE = "run with app.run(debug=True) only on localhost"


class Settings:
    debug = True


def worker(task):
    task.run(debug=True)
    return app
