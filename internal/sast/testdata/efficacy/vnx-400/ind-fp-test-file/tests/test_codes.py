from flask import request


def test_count(client):
    with client.application.test_request_context("/codes?count=3"):
        n = request.args.get("count", type=int)
        assert len(list(range(n))) == 3
