from flask import Blueprint, current_app, jsonify

admin = Blueprint("admin", __name__)


@admin.route("/admin/config")
def show_config():
~>    return jsonify({k: str(v) for k, v in current_app.config.items()})
