import urllib.request

PLUGIN_URL = "https://plugins.example.com/latest/plugin.py"


def install_plugin():
~>    exec(urllib.request.urlopen(PLUGIN_URL).read().decode("utf-8"), {})
