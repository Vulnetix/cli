def handler(request):
    base = request.args.get("name")
    path = "/data/scripts/%s.py" % base
~>  execfile(path)
