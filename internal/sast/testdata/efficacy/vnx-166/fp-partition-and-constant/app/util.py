from flask import request

VERSION = "1.2.3"


def minor():
    return VERSION.split(".")[1]


def token():
    header = request.headers.get("Authorization", "")
    scheme, _, value = header.partition(" ")
    return value


def mask(network):
    return int(network.split("/")[1])
