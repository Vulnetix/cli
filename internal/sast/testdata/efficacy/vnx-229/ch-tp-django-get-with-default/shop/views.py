from django.core.paginator import Paginator
from django.shortcuts import render


def product_list(request):
~>    page = int(request.GET.get("page", 1))
    paginator = Paginator(Product.objects.all(), 25)
    return render(request, "list.html", {"page": paginator.page(page)})
