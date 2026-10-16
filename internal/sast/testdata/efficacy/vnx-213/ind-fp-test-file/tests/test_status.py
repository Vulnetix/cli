import os

from flask import jsonify


def test_env_roundtrip(app):
    with app.test_request_context():
        resp = jsonify(environment=dict(os.environ))
        assert resp.status_code == 200
