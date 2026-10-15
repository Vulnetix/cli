from flask import jsonify


def fake_view():
    try:
        raise ValueError("x")
    except ValueError as e:
        return jsonify({"error": str(e)})
