from flask import Blueprint, jsonify, request

from app.models import Item

items_bp = Blueprint("items", __name__)


@items_bp.route("/items/<int:item_id>", methods=["PATCH"])
def patch_item(item_id):
    try:
        item = Item.query.get_or_404(item_id)
        item.update(request.get_json())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except PermissionError:
        return jsonify(error="forbidden"), 403
    return jsonify(item.to_dict())
