import urllib.request

PLUGIN_URL = "https://plugins.example.com/latest/installer.py"


def install():
~>    exec(urllib.request.urlopen(PLUGIN_URL).read().decode("utf-8"))


def run_remote_expr(httpx, name):
~>    return eval(httpx.get(f"https://rules.example.com/{name}.expr").text)
