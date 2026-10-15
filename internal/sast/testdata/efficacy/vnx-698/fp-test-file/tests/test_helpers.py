import flask


def test_redirect_inside_context(app):
    with app.test_request_context():
        flask.redirect("other")
        assert flask.request.path == "/"
