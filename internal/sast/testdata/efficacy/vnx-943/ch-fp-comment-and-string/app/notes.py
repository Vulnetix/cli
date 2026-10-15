# Never do this: db.users.find({"$where": "this.name == '%s'" % name})
WARNING = "db.users.find(json.loads(request.data)) lets a client send operators"


def explain():
    return WARNING
