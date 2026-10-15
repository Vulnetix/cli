from app import app


@app.route("/admin/test-only")
def helper():
    return "x"


def test_admin(client):
    # @app.route("/admin/users")
    assert client.get("/admin/users").status_code == 403
