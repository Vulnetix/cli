from django.http import HttpResponse


def save(request):
    user = request.POST.get("user")
    role = request.POST.get("role")
    with open("/srv/roles.txt", "a") as out:
~>        out.write(user + ":" + role + "\n")
~>        out.write("|".join([user, role, request.POST.get("team")]) + "\n")
~>        out.write("%s,%s\n" % (user, role))
    return HttpResponse("saved")
