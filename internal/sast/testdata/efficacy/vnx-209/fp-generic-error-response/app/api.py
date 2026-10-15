from flask import jsonify
import traceback


def handler(error):
    app.logger.error(traceback.format_exc())
    return jsonify({"error": "internal error"}), 500
