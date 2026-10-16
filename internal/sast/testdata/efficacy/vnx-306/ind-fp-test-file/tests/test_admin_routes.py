from flask import Flask


def make_app():
    app = Flask(__name__)

    @app.route("/admin/reset", methods=["POST"])
    def reset():
        return "ok"

    return app


def test_reset_route():
    client = make_app().test_client()
    assert client.post("/admin/reset").status_code == 200
