from django import forms


def handler(request):
    data = request.POST.get("data")
    q = request.session.get("query")
    return q.strip() if q else data


def render(template):
    page = template.get("body")
    return page.text if page else ""
