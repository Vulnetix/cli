import traceback

from flask import jsonify


def test_error_payload_shape(app):
    with app.test_request_context():
        resp = jsonify({"trace": traceback.format_exc()})
        assert resp.status_code == 200
