from django.views.decorators.csrf import csrf_exempt


~>@csrf_exempt  # HACK: disable CSRF until the mobile client sends the token
def webhook(request):
    return process(request.body)
