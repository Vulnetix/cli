from flask import request, jsonify


@app.route("/profile", methods=["PUT"])
def update_profile():
    payload = request.get_json()
    current = current_user()
    db.session.delete(current.profile)
~>    profile = Profile(**payload)
    current.profile = profile
    db.session.commit()
    return jsonify(profile.as_dict())
