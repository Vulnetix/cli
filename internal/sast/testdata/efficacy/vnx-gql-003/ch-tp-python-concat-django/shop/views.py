import requests
from django.http import JsonResponse


def order_lookup(request):
    order_id = request.GET["order"]
~>    query = "{ order(id: \"" + order_id + "\") { total status } }"
    resp = requests.post("https://api.internal/graphql", json={"query": query})
    return JsonResponse(resp.json())
