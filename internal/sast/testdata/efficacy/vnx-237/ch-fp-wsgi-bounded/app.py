from urllib.parse import parse_qs


def application(environ, start_response):
    query = parse_qs(environ["QUERY_STRING"], max_num_fields=50)
    body = parse_qs(environ["wsgi.input"].read(4096).decode(), max_num_fields=100)
    start_response("200 OK", [])
    return [repr((query, body)).encode()]
