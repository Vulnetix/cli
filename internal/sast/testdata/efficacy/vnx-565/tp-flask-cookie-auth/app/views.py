from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/dashboard")
def dashboard():
    # Reported by VNX-784 (a security decision on a cookie), not by this rule.
    if request.cookies.get("logged_in") != "yes":
        abort(401)
~>    username = request.cookies.get('username')
    account = Account.query.filter_by(username=username).first()
    return account.render()
