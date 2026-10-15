import requests

# Never do this: r = requests.get(request.args.get("url")); return r.content
HELP = "requests.get(request.args['url']) then return r.text is an open proxy"


def fetch_status():
    r = requests.get("https://status.example.com/api")
    return r.text
