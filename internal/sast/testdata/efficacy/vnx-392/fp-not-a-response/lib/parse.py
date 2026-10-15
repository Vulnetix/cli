import json


def parse(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return {"error": "invalid json"}


def fallback(data):
    try:
        return data["value"]
    except KeyError:
        return {"value": None}
