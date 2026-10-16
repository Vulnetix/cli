from flask import Flask, request, abort, session

from .models import User

app = Flask(__name__)


@app.route("/recover", methods=["POST"])
def recover():
    """Reset the password once the security question is answered."""
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
~>    if user.security_answer.lower() == request.form["answer"].lower():
        session["reset_user"] = user.id
        return "", 204
    abort(403)
