from flask import request
# the dao must not read request.form itself
from app.dao import item_dao


def test_dao(client):
    with client.application.test_request_context("/?a=1"):
        assert request.args["a"] == "1"
