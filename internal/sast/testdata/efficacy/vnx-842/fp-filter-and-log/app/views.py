from flask import request, jsonify


def list_users():
    users = User.query.filter_by(role=request.args.get("role")).all()
    staff = User.objects.filter(is_staff=request.GET.get("staff") == "1")
    return jsonify([u.to_dict() for u in users])
