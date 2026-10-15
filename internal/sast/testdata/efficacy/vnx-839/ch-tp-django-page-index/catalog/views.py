from django.http import Http404, JsonResponse

PAGES = ["intro", "pricing", "faq", "contact"]


def page(request):
    n = int(request.GET.get("page", "0"))
~>    if n >= len(PAGES):
        raise Http404()
    return JsonResponse({"page": PAGES[n]})
