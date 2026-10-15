ALLOWED = {"name", "email"}


def update(request):
    data = request.get_json()
    fields = {k: v for k, v in data.items() if k in ALLOWED}
    User.query.filter_by(id=g.user.id).update(fields)
    profile = Profile(**fields)
    Profile.objects.create(name=data["name"], email=data["email"])
    clean = {k: v for k, v in request.json.items() if k in ALLOWED}
    return Account(**clean)
