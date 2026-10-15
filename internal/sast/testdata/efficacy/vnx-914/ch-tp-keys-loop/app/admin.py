from django.http import JsonResponse


def bulk_update(request, obj):
    for attr in request.POST.keys():
~>        setattr(obj, attr, request.POST[attr])
    obj.save()
    return JsonResponse({"ok": True})
