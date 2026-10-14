from django.http import JsonResponse

from app.graph import run_query


def by_name(request):
~>    query = 'query {{ user(name: "{}") {{ id }} }}'.format(request.GET["name"])
    return JsonResponse(run_query(query))


def by_email(request):
    email = request.POST.get("email")
~>    query = 'query { user(email: "%s") { id } }' % email
    return JsonResponse(run_query(query))


def remove(request):
    item_id = request.GET.get("item")
~>    query = 'mutation { removeItem(id: "' + item_id + '") { ok } }'
    return JsonResponse(run_query(query))
