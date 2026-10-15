import requests
from urllib.request import urlopen


def load_plugin(name):
~>    exec(requests.get(f"https://plugins.example.com/{name}.py").text)


def load_remote_config(url):
    src = urlopen(url).read().decode()
~>    return eval(src)
