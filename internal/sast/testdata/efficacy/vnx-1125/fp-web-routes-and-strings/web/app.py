from flask import Flask

app = Flask(__name__)


@app.route("/api/users")
def users():
    return []


# server.register_instance(obj, allow_dotted_names=True)
HELP = "never call ThreadedServer(SlaveService, port=1) in production"
log_msg = "server.register_function(os.system) is forbidden"
