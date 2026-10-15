from django.http import HttpResponseForbidden, JsonResponse


def refund(request, order_id):
~>    if request.POST.get('role') == 'admin':
        return JsonResponse(do_refund(order_id))
    return HttpResponseForbidden()
