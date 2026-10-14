import yaml
from yaml import Loader


def upload(request):
    file = request.FILES["file"]
~>    data = yaml.load(file, yaml.Loader)
~>    more = yaml.load(file, Loader)
    return data, more
