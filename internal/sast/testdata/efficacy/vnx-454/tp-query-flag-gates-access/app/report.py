from django.http import JsonResponse


def export(request):
~>    if request.GET.get( 'is_staff' ) == "true":
        return JsonResponse(all_records(), safe=False)
    return JsonResponse([], safe=False)


def flask_export():
    from flask import request
~>    if request.args.get("admin"):
        return dump_everything()
    return "{}"
