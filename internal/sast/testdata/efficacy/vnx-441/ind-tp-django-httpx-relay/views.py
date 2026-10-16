import httpx
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET


@require_GET
def fetch_feed(request):
    feed_url = request.GET.get("feed")
    if feed_url is None:
        return JsonResponse({"error": "missing feed"}, status=400)
    with httpx.Client(timeout=5.0) as client:
~>        r = client.get(feed_url)
    return HttpResponse(r.text, content_type="application/rss+xml")
