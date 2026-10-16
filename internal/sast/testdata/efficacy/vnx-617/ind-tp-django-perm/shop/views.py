from django.http import HttpResponse


def refund(request, order_id):
~>    assert request.user.is_superuser, "admins only"
    return HttpResponse("refunded")
