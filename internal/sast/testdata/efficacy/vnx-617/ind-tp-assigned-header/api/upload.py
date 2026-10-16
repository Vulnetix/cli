def upload(request):
    size = int(request.headers.get("content-length", "0"))
~>    assert size < 10_000_000
    return save(request.body)
