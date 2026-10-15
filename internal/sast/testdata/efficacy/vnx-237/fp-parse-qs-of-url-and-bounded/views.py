from urllib.parse import parse_qs, urlparse

DATA_UPLOAD_MAX_NUMBER_FIELDS = 2000


def callback(url):
    params = parse_qs(urlparse(url).query)
    return params


def handle(request):
    form = parse_qs(request.body.decode(), max_num_fields=100)
    return form
