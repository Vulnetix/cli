from django.http import HttpResponse


def greet(request):
    username = request.GET.get("name", "")
~>    username = username.replace("<script>", "").replace("</script>", "")
    return HttpResponse("Hello " + username)


def comment(request):
    body = request.POST["body"]
~>    body = re.sub(r"<script.*?>", "", body, flags=re.I)
    return HttpResponse(body)
