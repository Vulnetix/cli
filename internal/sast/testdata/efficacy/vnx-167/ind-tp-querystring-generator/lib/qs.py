from urllib.parse import unquote_plus


def parse_query(query):
    params = {}
~>    for key, value in (part.split("=") for part in query.split("&") if part):
        params[unquote_plus(key)] = unquote_plus(value)
    return params
