from flask import request, g


def principal():
~>    merged = {**g.claims, **request.json}
    return merged


def principal2(token_claims):
~>    return dict(token_claims, **request.args)
