from flask import abort, request

from .registry import clients


def authenticate_client():
    client_id = request.form["client_id"]
    client_secret = request.form["client_secret"]
    client = clients.get(client_id)
    if client is None or not client.check_secret(client_secret):
~>        abort(401, "invalid client credentials for %s: %s" % (client_id, client_secret))
    return client
