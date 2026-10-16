from flask_cors import CORS


def test_wildcard_header_present(client):
    resp = client.get("/ping")
    assert resp.headers["Access-Control-Allow-Origin"] == "*"


def build(app):
    # CORS(app) would open the API to every site; we scope it instead.
    CORS(app, resources={r"/public/*": {"origins": "https://app.shop.example"}})
    return app
