# Never do this: user.groups.add(Group.objects.get(name=request.POST["group"]))
HELP = "The old handler copied role=request.form['role'] straight onto the user."


def describe():
    return "user.role = request.json['role'] is mass assignment"
