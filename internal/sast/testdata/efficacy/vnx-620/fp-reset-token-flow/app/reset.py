@bp.route("/reset/<token>", methods=["POST"])
def reset_with_token(token):
    user_id = load_reset_token(token, max_age=3600)
    if user_id is None:
        abort(403)
    user = User.query.get(user_id)
    new_password = request.form["new_password"]
    user.set_password(new_password)
    db.session.commit()
