from flask import request, jsonify


@app.post("/users")
def create():
~>    email = request.json["email"].lower()
~>    role = request.get_json().get("role", "user").strip()
    return jsonify(email=email, role=role)
