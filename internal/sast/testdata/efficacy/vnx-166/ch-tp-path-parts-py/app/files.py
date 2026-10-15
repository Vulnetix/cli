from flask import request


def tenant():
    parts = request.path.split("/")
~>    return parts[3]
