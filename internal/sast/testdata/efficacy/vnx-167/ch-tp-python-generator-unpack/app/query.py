def parse_query(qs):
    params = {}
~>    for key, value in (pair.split("=") for pair in qs.split("&")):
        params[key] = value
    return params


def parse_headers(header_items):
~>    return {k: v for k, v in (item.split(":") for item in header_items)}
