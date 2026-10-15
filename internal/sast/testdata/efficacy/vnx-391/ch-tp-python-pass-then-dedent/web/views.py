def start(request, name):
    try:
        row = Store.get(name)
        exists = True
~>    except:
        pass

    port = pick_port()
    if port is None:
        return error("no port")
    return ok(port)
