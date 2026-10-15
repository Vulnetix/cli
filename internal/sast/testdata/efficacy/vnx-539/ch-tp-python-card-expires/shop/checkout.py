from django.http import JsonResponse


def save_card(request):
    card = request.POST["card_number"]
    expiry = compute_expiry(request)
    response = JsonResponse({"ok": True})
~>    response.set_cookie(key="card_number", value=card, expires=expiry)
    return response
