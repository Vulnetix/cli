# A Flask admin view with no decorator or check in front of it. VNX-306
# reports the Python form of this defect; this rule reports JavaScript,
# TypeScript and Go routes.
from flask import Blueprint, jsonify

from .jobs import rebuild_index

maintenance = Blueprint("maintenance", __name__)


@maintenance.post("/admin/index/rebuild")
def rebuild():
    rebuild_index()
    return jsonify({"queued": True})
