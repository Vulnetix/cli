from django.shortcuts import render


def listing(request):
    page = request.GET.get("page", 1)
    size = request.GET["size"]
~>    offset = (int(page) - 1) * int(size)
    items = Item.objects.all()[offset:offset + 20]
    return render(request, "list.html", {"items": items})
