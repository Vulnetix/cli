from django.http import JsonResponse

from shop import handlers


def dispatch(request):
    action = request.GET.get("action", "list")
~>    handler = getattr(handlers, action)
    return JsonResponse(handler(request))


def dispatch_post(request):
~>    fn = getattr(handlers, request.POST["op"], None)
    return JsonResponse(fn(request))
