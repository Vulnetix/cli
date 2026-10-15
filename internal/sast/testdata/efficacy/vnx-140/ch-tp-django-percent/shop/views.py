from django.http import HttpResponse


def record(request):
    with open("/var/log/shop/actions.log", "a") as log:
~>        log.write("%s|%s\n" % (request.POST.get("user"), "checkout"))
    return HttpResponse("done")
