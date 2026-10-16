from urllib.parse import parse_qs, urlparse


def query_of(url):
    return parse_qs(urlparse(url).query)


def body_of(request):
    body = request.body.decode()
    return parse_qs(body, max_num_fields=200)
