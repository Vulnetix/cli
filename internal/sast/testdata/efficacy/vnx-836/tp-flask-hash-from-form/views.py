from flask import request, abort


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first()
~>    if user is None or user.password_hash != request.form["password_hash"]:
        abort(401)
    login_user(user)


@app.post("/api/token")
def token():
    account = load(request.json["user"])
~>    if request.json.get("hashedPassword") == account.hashed_password:
        return issue_token(account)
    abort(401)
