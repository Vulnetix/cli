import yaml


def webhook(request):
~>    payload = yaml.load(
        request.data,
        Loader=yaml.UnsafeLoader,
    )
~>    other = yaml.load(
        request.data
    )
    return payload, other
