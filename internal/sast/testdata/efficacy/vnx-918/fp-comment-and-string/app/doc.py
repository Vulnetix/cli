# requests.get(request.args.get("url")) is SSRF
HELP = "never call requests.get(request.args['u'])"
