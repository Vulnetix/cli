def check_cors(resp):
    # Flag servers that answer with Access-Control-Allow-Origin: *
    if resp.headers.get("Access-Control-Allow-Origin") == "*":
        return "wildcard"
    assert resp.headers["Access-Control-Allow-Origin"] != "*"
    message = "Never send Access-Control-Allow-Origin: * with credentials"
    return message
