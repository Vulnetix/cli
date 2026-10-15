from flask import request, url_for


@app.route("/forgot", methods=["POST"])
def forgot():
    user = User.query.filter_by(email=request.form["email"]).first()
    token = make_reset_token(user)
~>    link = f"http://{request.host}/reset/{token}"
    send_reset_email(user.email, link)
    return "sent"


@app.route("/recover", methods=["POST"])
def recover():
    token = make_reset_token(current_user)
~>    reset_url = request.url_root + "reset?token=" + token
    send_reset_email(current_user.email, reset_url)
    return "sent"
