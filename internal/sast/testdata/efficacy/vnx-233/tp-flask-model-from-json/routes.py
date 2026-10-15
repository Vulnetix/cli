from flask import request, jsonify


@app.post("/users")
def create_user():
~>    user = User(** request.json)
    db.session.add(user)
~>    q = Order.query.filter_by(**request.args)
~>    payload = {**request.get_json(), "created_by": g.user.id}
    return jsonify(user.to_dict(), q.count(), payload)
