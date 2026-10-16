from flask import Flask

app = Flask(__name__)


@app.route("/admin/reset", methods=["POST"])
def reset_for_test():
    User.query.delete()
    return "ok"
