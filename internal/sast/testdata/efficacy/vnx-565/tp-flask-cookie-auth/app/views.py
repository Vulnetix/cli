from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/dashboard")
def dashboard():
~>    if request.cookies.get("logged_in") != "yes":
        abort(401)
~>    username = request.cookies.get('username')
    account = Account.query.filter_by(username=username).first()
    return account.render()
