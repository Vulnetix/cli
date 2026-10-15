from flask import Flask

app = Flask(__name__)


@app.route("/login", methods=["GET"])
def login_form():
    return render_form()


@app.route("/login", methods=["POST"])
def login_submit():
    return check_login()


@app.get("/items")
def get_items():
    return []


@app.post("/items")
def post_item():
    return {}
