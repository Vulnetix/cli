from flask import Blueprint, jsonify, request

from .models import Project

bp = Blueprint("projects", __name__)


@bp.route("/projects")
def list_projects():
~>    include_archived = bool(request.args.get("include_archived"))
    rows = Project.query_visible(include_archived=include_archived)
    return jsonify([p.to_dict() for p in rows])


@bp.route("/projects/<int:pid>", methods=["DELETE"])
def delete_project(pid):
    raw = request.form.get("notify")
~>    notify_owner = bool(raw)
    Project.delete(pid, notify_owner=notify_owner)
    return "", 204
