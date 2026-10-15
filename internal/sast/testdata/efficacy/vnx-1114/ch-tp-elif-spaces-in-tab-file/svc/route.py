def route(req):
	if req.method == "GET":
		return show(req)
~>    elif req.method == "POST":
		return save(req)
	return deny(req)
