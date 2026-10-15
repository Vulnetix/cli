import yaml as y


def documents(stream):
~>    for doc in y.load_all(stream):
        yield doc


def one(request):
    body = request.get_data()
~>    return y.load(body)
