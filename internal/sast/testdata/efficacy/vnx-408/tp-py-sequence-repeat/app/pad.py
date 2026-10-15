def pad(request):
    width = int(request.POST.get("width"))
~>    return "0" * width
