from flask import request, jsonify


@app.route("/invite", methods=["POST"])
def invite():
~>    email = request.json["email"].lower()
    Invite.create(email=email, team=current_team())
    return jsonify({"invited": email}), 201
