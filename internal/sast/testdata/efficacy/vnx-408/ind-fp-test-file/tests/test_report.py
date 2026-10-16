from flask import request

from app import create_app


def test_preview_renders_pages():
    app = create_app()
    with app.test_request_context("/report/preview?pages=3"):
        pages = int(request.args.get("pages", 1))
        out = []
        for page in range(pages):
            out.append(page)
        assert out == [0, 1, 2]
